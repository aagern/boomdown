  ## Boomstream download
  
  The script automates video download for your video for testing purposes.
  
  ### Requirements:
  
  * requests
  * cryptography
  * pytest
  * responses
  
  ### Usage:
  
  * Open the webpage with embedded video in Chrome Browser;
  * Dev Tools (F12);  
  * Put m3u8 in filter box;
  * Choose video size-quality (example=1080p) and start playing it;
  * See intercepted chunklist.m3u8 in Dev Tools, copy the "https://cdnv-m17.boomstream.com/.../chunklist.m3u8" address

  ### Run the script:
  
  ```shell
  cd boomdown
  source .venv/bin/activate
  python boomdown.py "https://cdnv-m17.boomstream.com/.../chunklist.m3u8" --output video.mp4
  ```
  
  Script does 7 tasks:
  * Parses #EXT-X-MEDIA-READY: from chunklist
  * Pulls all .ts HTTPS URLs from chunklist
  * Reads IV from #EXT-X-KEY:IV=0x...
  * Calls play.boomstream.com/api/process/<value> → 16-byte key
  * Fallback IV computation if not in playlist
  * Fetches a .ts, AES-128-CBC decrypts it
  * ffmpeg concat demuxer → MP4
  * Orchestrates the full pipeline