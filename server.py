from fastapi import FastAPI, UploadFile, File, Form
from pathlib import Path
# import shutil
# import vace_ltx_inferenceN  # your existing inference module

app = FastAPI(title="WAN VACE Outpainting API")

# @app.post("/outpaint/")
# async def outpaint(image: UploadFile = File(...)):
#     # save uploaded file temporarily
#     temp_path = Path("temp_input") / image.filename
#     temp_path.parent.mkdir(exist_ok=True)
#     with open(temp_path, "wb") as f:
#         shutil.copyfileobj(image.file, f)

#     # call your inference logic
#     result_path = vace_ltx_inferenceN.run_inference(str(temp_path))  # adjust based on your function

#     return {"result_path": str(result_path)}
 
@app.post("/outpaint/")
async def outpaint(file: UploadFile = File(...), target: str = Form(...)):
    if not file:
        return {"error": "No file uploaded"}
    if file.content_type not in ["video/mp4", "video/avi", "video/mov"]:
        return {"error": "Invalid file type, only mp4, avi, mov are allowed"}
    if target not in ["landscape", "portrait"]:
        return {"error": "Invalid target specified, Target should be 'landscape' or 'portrait'"}
    
    print("outpaint route")
    # command=time python vace/vace_pipeline.py --base ltx --task outpainting --direction 'left,right' --expand_ratio 1.0 --video "benchmarks/VACE-Benchmark/assets/examples/outpainting/output_video480p.mp4" --prompt "" --num_frames 501 --frame_rate 25 --num_inference_steps 12 --offload_to_cpu


@app.get("/")
async def print():
    return("hello world")