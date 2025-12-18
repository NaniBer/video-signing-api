import uuid
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import StreamingResponse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import base64
import hashlib
import shutil
import os


# --- Configuration ---
SIGNED_DIR = Path("files")
SIGNED_DIR.mkdir(exist_ok=True)
MASTER_KEY = b"my_super_secret_master_key"  # keep secret in production

app = FastAPI(title="Video Signing API with Extra Metadata")

# --- Helpers ---
def derive_private_key(asset_id: str) -> ed25519.Ed25519PrivateKey:
    seed = hashlib.sha256(MASTER_KEY + asset_id.encode()).digest()
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])

def run_cmd(cmd: list):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nstdout: {result.stdout}\nstderr: {result.stderr}")
    return result

def get_stream_hash(video_path: Path, include_audio: bool = True) -> str:
    """
    Compute a stable hash of video (and optionally audio) using ffmpeg.
    """
    maps = ["-map", "0:v:0"]
    if include_audio:
        maps += ["-map", "0:a?"]

    cmd = ["ffmpeg", "-v", "error", "-i", str(video_path)] + maps + ["-c", "copy", "-f", "hash", "-"]
    result = run_cmd(cmd)
    output = (result.stdout or "") + (result.stderr or "")
    for line in output.splitlines():
        if "=" in line:
            _, val = line.split("=", 1)
            return val.strip()
    raise RuntimeError("Failed to get stream hash from ffmpeg output")

def embed_metadata(video_path: Path, metadata: dict) -> Path:
    output_path = SIGNED_DIR / f"signed-{video_path.name}"
    cmd = ["ffmpeg", "-y", "-v", "error", "-i", str(video_path), "-c", "copy", "-movflags", "use_metadata_tags"]

    for k, v in metadata.items():
        # JSON encode complex types
        if isinstance(v, (dict, list, bool)):
            v_str = json.dumps(v)
        else:
            v_str = str(v)
        cmd += ["-metadata", f"{k}={v_str}"]

    cmd.append(str(output_path))
    run_cmd(cmd)
    return output_path

def extract_metadata(video_path: Path) -> dict:
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format_tags", "-of", "default=noprint_wrappers=1:nokey=0", str(video_path)],
        capture_output=True,
        text=True
    )
    tags = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            key, val = line.split("=", 1)
            tags[key.lower()] = val
    return tags

def add_watermark(input_path, watermark_image_path, output_path, scale_factor=1):
    """Adds a resizable watermark image to the bottom-right corner of a video using FFmpeg."""
    padding = 20
    filter_graph = (
        f"[1:v]scale=w=iw/{scale_factor}:h=ih/{scale_factor}[watermark]; "
        f"[0:v][watermark]overlay="
        f"x='if( lt(mod(t\\,8)\\,2), 20, "
        f"    if( lt(mod(t\\,8)\\,4), main_w-overlay_w-20, "
        f"        if( lt(mod(t\\,8)\\,6), main_w-overlay_w-20, 20)"
        f"    )"
        f")':"
        f"y='if( lt(mod(t\\,8)\\,2), 20, "
        f"    if( lt(mod(t\\,8)\\,4), 20, "
        f"        if( lt(mod(t\\,8)\\,6), main_h-overlay_h-20, main_h-overlay_h-20)"
        f"    )"
        f")'"
    )
    ffmpeg_command = [
        'ffmpeg',
        '-y',
        '-i', input_path,
        '-i', watermark_image_path,
        '-filter_complex', filter_graph,
        '-codec:a', 'copy',
        output_path
    ]

    print(f"Executing FFmpeg with scale factor: {scale_factor}")

    try:
        subprocess.run(ffmpeg_command, check=True, capture_output=True, text=True)
        print(f"Watermark successfully added and resized. Output saved to {output_path}")
        return output_path

    except subprocess.CalledProcessError as e:
        print(f"FFmpeg failed with an error. Check the command and inputs:\n{e.stderr}")
        return None

    except FileNotFoundError:
        print("Error: FFmpeg executable not found. Make sure it is installed and added to your system's PATH.")
        return None

@app.post("/sign")
async def sign_video_file(
    video_file: UploadFile = File(...),
    metadata_file: UploadFile = File(...),
    signer: str = "TaskManagerAV",
    watermark: bool = True,  
    watermark_text: str = "MyApp"  
):
    temp_files = []
    try:
        # 1) Read JSON metadata
        try:
            metadata_content = await metadata_file.read()
            extra_metadata = json.loads(metadata_content)
            if not isinstance(extra_metadata, dict):
                raise ValueError()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON file for metadata")

        # 2) Save uploaded video temporarily
        video_id = str(uuid.uuid4())
        temp_video_path = SIGNED_DIR / f"{video_id}-{video_file.filename}"
        with open(temp_video_path, "wb") as f:
            f.write(await video_file.read())
        temp_files.append(temp_video_path)

        # 2a) Add watermark if enabled
        if watermark:
            watermarked_path = SIGNED_DIR / f"watermarked-{video_id}-{video_file.filename}"
            add_watermark(
                input_path=temp_video_path,
                watermark_image_path="clean-logo.png", 
                output_path=watermarked_path,
            )
            temp_files.append(watermarked_path)
        else:
            watermarked_path = temp_video_path

        # 3) Compute hash + deterministic signature
        stream_hash = get_stream_hash(watermarked_path)
        private_key = derive_private_key(stream_hash)
        signature_b64 = base64.b64encode(private_key.sign(stream_hash.encode("utf-8"))).decode()
        timestamp = datetime.utcnow().isoformat() + "Z"

        # 4) Merge metadata
        metadata = {
            "video_id": video_id,
            "signature": signature_b64,
            "signer": signer,
            "timestamp": timestamp,
            "stream_hash": stream_hash,
            **{k.lower(): v for k, v in extra_metadata.items()}
        }

        # 5) Embed metadata
        output_path = embed_metadata(watermarked_path, metadata)
        temp_files.append(output_path)

        # -----------------------------
        # 6) C2PA SIGNING (FINAL STEP)
        # -----------------------------
        manifest_path = "manifests/minimal.json"
        c2pa_base = f"{video_id}-c2pa"
        c2pa_output = SIGNED_DIR / f"{c2pa_base}.mp4"
        c2pa_manifest_output = SIGNED_DIR / f"{c2pa_base}.manifest.json"

        cmd = [
            "c2patool",
            "--output", str(c2pa_output),
            "--manifest", manifest_path,
            str(output_path)
        ]

        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"C2PA signing failed: {e.output.decode()}")

        # 7) Build download URLs
        download_url = f"/download-temp/{c2pa_output.name}"
        manifest_url = f"/download-temp/{c2pa_manifest_output.name}"

        return {
            "status": "ok",
            "message": "Video signed with custom metadata AND C2PA.",
            "video_id": video_id,
            "filename": c2pa_output.name,
            "download_url": download_url,
            "manifest_url": manifest_url,
            "metadata_embedded": metadata,
            "watermark_applied": watermark,
            "watermark_text": watermark_text
        }

    finally:
        # Cleanup all temporary/intermediate files
        for fpath in temp_files:
            try:
                if fpath.exists():
                    fpath.unlink()
            except Exception as e:
                print(f"Warning: failed to delete temp file {fpath}: {e}")

# --- Auto-delete Download ---
@app.get("/download-temp/{filename}")
async def download_temp_video(filename: str):
    file_path = SIGNED_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    def file_iterator(path: Path, chunk_size: int = 8192):
        try:
            with open(path, "rb") as f:
                while chunk := f.read(chunk_size):
                    yield chunk
        finally:
            try:
                path.unlink()
            except Exception as e:
                print(f"Warning: failed to delete {path}: {e}")

    return StreamingResponse(
        file_iterator(file_path),
        media_type="video/mp4",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# --- Verify Endpoint ---
@app.post("/verify")
async def verify_video_file(
    file: UploadFile = File(...),
    include_audio: bool = Query(True, description="Include audio in stream hash during verification")
):
    verify_path = SIGNED_DIR / f"verify-{file.filename}"
    with open(verify_path, "wb") as out_file:
        await file.seek(0)
        shutil.copyfileobj(file.file, out_file)

    try:
        tags = extract_metadata(verify_path)
        signature_b64 = tags.get("tag:signature")
        if not signature_b64:
            return {"verified": False, "message": "No signature metadata found.", "metadata": tags}

        stream_hash_meta = tags.get("tag:stream_hash")
        if not stream_hash_meta:
            return {"verified": False, "message": "No stream_hash metadata found, cannot verify.", "metadata": tags}

        private_key = derive_private_key(stream_hash_meta)
        public_key = private_key.public_key()
        signature_bytes = base64.b64decode(signature_b64)

        recomputed = get_stream_hash(verify_path, include_audio=include_audio)
        sanity_mismatch = recomputed != stream_hash_meta

        try:
            public_key.verify(signature_bytes, recomputed.encode("utf-8"))
            verified = True
            message = "Video is authentic!"
        except InvalidSignature:
            verified = False
            message = "Signature verification failed, video may have been tampered with."

    finally:
        try:
            verify_path.unlink()
        except Exception as e:
            print(f"Warning: failed to delete temp file {verify_path}: {e}")

    return {
        "verified": verified,
        "message": message,
        "metadata": tags,
        "recomputed_stream_hash": recomputed,
        "sanity_mismatch": sanity_mismatch
    }

@app.get("/")
async def root():
    return {"message": "Welcome to the Video Signing API with Extra Metadata!"}