import uuid
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Form
from fastapi.responses import StreamingResponse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import base64
import hashlib
import shutil
import os
import logging
import boto3
from botocore.client import Config


# --- Configuration ---
SIGNED_DIR = Path("files")
SIGNED_DIR.mkdir(exist_ok=True)
MASTER_KEY = b"my_super_secret_master_key"  # keep secret in production

app = FastAPI(title="Video Signing API with Extra Metadata")
logging.basicConfig(level=logging.INFO)
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

def add_watermark(
    input_path: Path,
    watermark_image_path: str,
    output_path: Path,
    isPrivate: bool,
    scale_factor: float = 1.0
):
    """
    Adds a watermark to images or videos using FFmpeg.
    - Images: no audio handling
    - Videos: audio stream preserved
    """

    # 1️⃣ Detect media type
    is_image = input_path.suffix.lower() in [".jpg", ".jpeg", ".png", ".webp"]

    # 2️⃣ For videos, get dimensions and calculate watermark size
    if not is_image:
        # Get video dimensions using ffprobe
        probe_result = subprocess.run(
            ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
             "stream=width,height", "-of", "json", str(input_path)],
            capture_output=True, text=True, check=True
        )
        import json
        video_info = json.loads(probe_result.stdout)
        video_width = video_info['streams'][0]['width']

        # Calculate watermark dimensions (50% of video width)
        max_w_percent = 0.15
        watermark_width = int(video_width * max_w_percent)

        filter_graph = (
            f"[1:v]scale={watermark_width}:-1[watermark]; "
            f"[0:v][watermark]overlay=x=20:y=main_h-overlay_h-20"
        )
    else:
        # Images - use scale2ref
        max_w_percent = 0.05
        max_h_percent = 0.05
        filter_graph = (
            f"[1:v][0:v]scale2ref="
            f"w=main_w*{max_w_percent}:"
            f"h=main_h*{max_h_percent}:"
            f"force_original_aspect_ratio=decrease"
            f"[watermark][base]; "
            f"[base][watermark]overlay=x=20:y=main_h-overlay_h-20"
        )
    # 3️⃣ Build ffmpeg command
    ffmpeg_command = [
        "ffmpeg",
        "-y",
        "-i", str(input_path),
        "-i", watermark_image_path,
        "-filter_complex", filter_graph,
    ]
    # 4️⃣ Preserve audio only for videos
    if not is_image:
        ffmpeg_command += ["-codec:a", "copy"]
    

    ffmpeg_command.append(str(output_path))


    print(f"Executing FFmpeg | image={is_image} | private={isPrivate}")

    # 5️⃣ Execute
    try:
        subprocess.run(
            ffmpeg_command,
            check=True,
            capture_output=True,
            text=True
        )
        print(f"ffmpeg_command: {ffmpeg_command}")
        print(f"Watermark added successfully → {output_path}")
        return output_path

    except subprocess.CalledProcessError as e:
        logging.error("FFmpeg failed:")
        logging.error(f"Command: {ffmpeg_command}")
        logging.error(f"stderr: {e.stderr}")
        logging.error(f"stdout: {e.stdout}")
        return None

    except FileNotFoundError:
        logging.error("FFmpeg not found. Make sure it is installed and on PATH.")
        return None


def embed_image_metadata(image_path: Path, metadata: dict) -> Path:
    """
    Embeds metadata into an image using XMP via exiftool.
    Stores the full metadata dict as JSON in XMP:Description.
    """

    metadata_json = json.dumps(metadata, ensure_ascii=False)

    cmd = [
        "exiftool",
        "-overwrite_original",
        f"-XMP-dc:Description={metadata_json}",
        f"-XMP-dc:Creator={metadata.get('signer', 'TaskManagerAV')}",
        str(image_path),
    ]

    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return image_path

    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Failed to embed image metadata: {e.output.decode()}"
        )


S3_CONFIG = {
    "region_name": "us-west-2",
    "endpoint_url": "https://s3.cloud.ideeza.com",
    "aws_access_key_id": '76f2914ce35146dca846ca086563f973',
    "aws_secret_access_key": '06670e224d6f4600852d35ec363bcf7d',
}
BUCKET_NAME = 'cdnideeza'

s3_client = boto3.client(
    "s3",
    region_name=S3_CONFIG["region_name"],
    endpoint_url=S3_CONFIG["endpoint_url"],
    aws_access_key_id=S3_CONFIG["aws_access_key_id"],
    aws_secret_access_key=S3_CONFIG["aws_secret_access_key"],
    config=Config(signature_version="s3v4"),
)
def upload_file_to_s3(file_path: str, folder: str) -> str:
    """Uploads a local file to S3 and returns the public URL."""
    object_key = f"{folder}/{os.path.basename(file_path)}"
    
    s3_client.upload_file(
        file_path,
        BUCKET_NAME,
        object_key,
        ExtraArgs={"ACL": "public-read"}
    )
    
    return f"{S3_CONFIG['endpoint_url']}/{BUCKET_NAME}/{object_key}"



@app.post("/sign")
async def sign_video_file(
    media_file: UploadFile = File(...),
    metadata_file: UploadFile = File(...),
    isPrivate: bool = Form(True),
):
    temp_files = []
    output_path = None
    c2pa_output = None

    try:
        # 1️⃣ Read JSON metadata
        try:
            metadata_content = await metadata_file.read()
            extra_metadata = json.loads(metadata_content)
            if not isinstance(extra_metadata, dict):
                raise ValueError()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON file for metadata")

        # 2️⃣ Detect media type
        content_type = media_file.content_type or ""
        is_image = content_type.startswith("image/")
        is_video = content_type.startswith("video/")


        if not (is_image or is_video):
            raise HTTPException(
                status_code=400,
                detail="Unsupported file type. Only images and videos are allowed."
            )
        # 3️⃣ Save uploaded media
        media_id = str(uuid.uuid4())
        temp_media_path = SIGNED_DIR / f"{media_id}-{media_file.filename}"

        with open(temp_media_path, "wb") as f:
            f.write(await media_file.read())

        temp_files.append(temp_media_path)
        logging.info("Watermarking started | is_image=%s | isPrivate=%s ", is_image, isPrivate)
    
        # 4️⃣ Watermark (shared logic)
 
        watermarked_path = SIGNED_DIR / f"watermarked-{media_id}{temp_media_path.suffix}"

        if is_video:
            watermark_image_path = (
                "publicLogo.gif"
            )
        else:
            watermark_image_path = (
                "clean-logo.jpeg"
            )

        result=add_watermark(
            input_path=temp_media_path,
            watermark_image_path=watermark_image_path,
            output_path=watermarked_path,
            isPrivate=isPrivate,
        )
        if result is None or not watermarked_path.exists():
            raise HTTPException(
                status_code=500,
                detail="Watermarking failed. Check FFmpeg logs."
            )
  

        temp_files.append(watermarked_path)


        # 5️⃣ Hash + deterministic signature
        stream_hash = get_stream_hash(watermarked_path)
        private_key = derive_private_key(stream_hash)
        signature_b64 = base64.b64encode(
            private_key.sign(stream_hash.encode("utf-8"))
        ).decode()
        timestamp = datetime.utcnow().isoformat() + "Z"

        # 6️⃣ Merge metadata
        metadata = {
            "media_id": media_id,
            "signature": signature_b64,
            "timestamp": timestamp,
            "stream_hash": stream_hash,
            **{k.lower(): v for k, v in extra_metadata.items()}
        }

        # 7️⃣ Embed metadata
        if is_image:
            output_path = embed_image_metadata(watermarked_path, metadata)
        else:
            output_path = embed_metadata(watermarked_path, metadata)

        temp_files.append(output_path)

        # 8️⃣ C2PA signing
        manifest_path = "manifests/minimal.json"
        c2pa_base = f"{media_id}-c2pa"

        output_ext = ".mp4" if is_video else output_path.suffix
        c2pa_output = SIGNED_DIR / f"{c2pa_base}{output_ext}"
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
            raise HTTPException(
                status_code=500,
                detail=f"C2PA signing failed: {e.output.decode()}"
            )
        folder="signed_videos"
    
        print(f"output path → {output_path}")

        url = upload_file_to_s3(output_path, folder)
        # 9️⃣ Response
        return {
            "URL":url,
            "Success": "true"
        }
    finally: 
        # 🔟 Cleanup
        for fpath in temp_files:
            try:
                if fpath.exists():
                    fpath.unlink()
            except Exception as e:
                print(f"Warning: failed to delete temp file {fpath}: {e}")
            
        # Cleanup c2pa output if exists
        if c2pa_output and c2pa_output.exists():
            try:
                c2pa_output.unlink()
            except Exception as e:
                print(f"Warning: failed to delete c2pa_output {e}")

        # Cleanup signed output if exists
        if output_path and output_path.exists():
            try:
                output_path.unlink()
            except Exception as e:
                print(f"Warning: failed to delete output_path {e}")


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