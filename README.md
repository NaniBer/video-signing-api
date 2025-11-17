Video Signing API with Extra Metadata

Securely sign videos, embed metadata, and verify authenticity

This FastAPI project lets you upload videos, attach structured metadata, sign them using Ed25519 keys derived from the video hash, and verify the authenticity of any signed video. Perfect for content integrity, digital provenance, or any situation where verifying video authenticity is a must.

🚀 Features

Sign Videos: Upload a video and a JSON metadata file, generate a signed video with embedded metadata.

Auto-delete Downloads: Download signed videos via a temporary link that deletes the file after download.

Metadata Rich: Embed any additional metadata fields you want (owner info, AI tools used, tampering status, description, category, location, etc.).

Verify Videos: Check if a video has been tampered with by recomputing stream hashes and verifying signatures.

Unique Video IDs: Each video gets a UUID for easy tracking and reference.

🛠 Tech Stack

FastAPI – Super fast Python API framework.

FFmpeg / FFprobe – For computing media hashes and embedding metadata.

Cryptography (Ed25519) – For signing and verifying video hashes.

Python 3.11+ – Keep your environment fresh.

📦 Installation

Clone the repo:

git clone https://github.com/your-username/video-signing-api.git
cd video-signing-api

Create and activate a virtual environment:

python -m venv venv
source venv/bin/activate # Linux/Mac
venv\Scripts\activate # Windows

Install dependencies:

pip install -r requirements.txt

Make sure FFmpeg is installed and available in your PATH.

⚡ Usage

Run the API:

uvicorn app:app --reload

Endpoints
Sign a Video
POST /sign

Files:

video_file (MP4 or other video formats)

metadata_file (JSON file with extra metadata)

Query Parameters:

signer (optional, default: TaskManagerAV)

Returns:

{
"video_id": "uuid",
"filename": "signed-video.mp4",
"download_url": "/download-temp/signed-video.mp4",
"metadata_embedded": {...}
}

Download Signed Video (auto-delete)
GET /download-temp/{filename}

Verify a Video
POST /verify

Files:

file (signed video)

Query Parameters:

include_audio (optional, default: true)

Returns:

{
"verified": true,
"message": "Video is authentic!",
"metadata": {...},
"recomputed_stream_hash": "...",
"sanity_mismatch": false
}

📝 Example Metadata JSON
{
"owner": "ideeza",
"tampered": false,
"ai_tools_used": ["none"],
"description": "Short description of the video content",
"category": "tutorial",
"tags": ["education", "example"],
"source": "original_recording",
"location": "Ethiopia",
"notes": "Any additional info"
}

🔐 Security Notes

MASTER_KEY: Keep your master key secret! It’s used for deterministic signing.

Deterministic Key: Ed25519 private keys are derived from video stream hash + master key.

🧩 Contributing

Pull requests and stars are welcome! 💖

Fork it, add features, improve metadata handling, or optimize FFmpeg calls.

Open an issue if something is funky.
