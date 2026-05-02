# extract_binaries.py
import subprocess, json, pathlib, re, shutil

def extract_task_binaries(task_id: str, metadata: dict):
    """Extract vul/fix binaries from Docker images and push to Google Drive"""
    match = re.match(r'([^:]+):(\d+)', task_id)
    if not match:
        print(f"⚠️ Could not parse task_id: {task_id}")
        return False
    
    project, issue = match.groups()
    hash_id = metadata.get("task_id")
    
    base_dir = pathlib.Path("cybergym-server-data") / project / issue
    
    for variant in ["vul", "fix"]:
        archive_name = f"{project}_{issue}_{variant}.tar.gz"
        archive_path = base_dir / archive_name
        remote_dir = f"gdrive:cybergym-backups/{project}/{issue}/"
        remote_file = f"{remote_dir}{archive_name}"
        
        # --- NEW: Check if it already exists on Google Drive ---
        print(f"🔍 Checking Drive for {archive_name}...")
        check_res = subprocess.run(["rclone", "lsf", remote_file], capture_output=True, text=True)
        if check_res.returncode == 0 and check_res.stdout.strip():
            print(f"⏭️  Already backed up! Skipping {variant} extraction.")
            continue
        # -------------------------------------------------------

        image_tags = []
        if hash_id:
            image_tags.append(f"n132/arvo:{hash_id}-{variant}")
        image_tags.append(f"n132/arvo:{issue}-{variant}")
        
        image = None
        for tag in image_tags:
            # Check local first
            result = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True)
            if result.stdout.strip():
                image = tag
                break
            
            # If not local, attempt to pull it from the internet
            print(f"⏳ Image not local. Pulling {tag} from Docker Hub...")
            pull_result = subprocess.run(["docker", "pull", tag], capture_output=True)
            if pull_result.returncode == 0:
                image = tag
                break
        
        if not image:
            print(f"⚠️ Image not found locally or on Docker Hub for {task_id}-{variant}")
            continue
        
        out_dir = base_dir / variant / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"📦 Extracting {image} → {out_dir}")
        container = subprocess.run(
            ["docker", "create", "--name", f"temp_extract_{issue}_{variant}", image],
            capture_output=True, text=True
        ).stdout.strip()
        
        if not container:
            print(f"❌ Failed to create container for {image}")
            continue
        
        try:
            # Copy /out from container to host
            subprocess.run(["docker", "cp", f"{container}:/out/.", str(out_dir)], check=True, capture_output=True)
            print(f"✅ Extracted to {out_dir}")
            
            # Compress the variant directory
            print(f"🗜️ Compressing to {archive_path}...")
            subprocess.run(["tar", "-czf", str(archive_path), "-C", str(base_dir), variant], check=True)
            
            # Upload to Google Drive using rclone
            print(f"☁️ Uploading to Google Drive: {remote_dir}")
            subprocess.run(["rclone", "copy", str(archive_path), remote_dir], check=True)
            
            print("🧹 Cleaning up local disk...")
            shutil.rmtree(out_dir)
            archive_path.unlink()
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Operation failed: {e.stderr.decode()[:200]}")
        finally:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    
    return True

if __name__ == "__main__":
    tasks = json.loads(pathlib.Path("subset_20.json").read_text())
    
    print(f"🔹 Extracting binaries for {len(tasks)} tasks...")
    for tid in tasks:
        print(f"\n[{tasks.index(tid)+1}/{len(tasks)}] {tid}")
        
        task_dir = pathlib.Path(f"./tasks/{tid.replace(':', '_')}")
        script = task_dir / "submit.sh"
        metadata = {}
        
        # Make submit.sh optional. If it's missing, just use the issue number.
        if script.exists():
            content = script.read_text()
            match = re.search(r"-F\s+'metadata=({.*?})'", content, re.DOTALL)
            if match:
                metadata = json.loads(match.group(1))
        else:
            print(f"ℹ️ submit.sh not found. Relying on default issue tags.")
            
        extract_task_binaries(tid, metadata)
    
    print("\n✅ Extraction and Google Drive upload complete.")