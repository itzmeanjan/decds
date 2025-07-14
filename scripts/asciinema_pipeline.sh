#!/usr/bin/bash

# Download and install asciinema and agg. They should be in $HOME/.cargo/bin.
cargo install --locked --git https://github.com/asciinema/asciinema
cargo install --git https://github.com/asciinema/agg

# Record some terminal activity and play it inside terminal.
asciinema record decds.cast
asciinema play decds.cast

# Convert asciinema file format to v2. Apparently v3 is not yet supported by agg, which I'll use for making a GIF.
asciinema convert -f asciicast-v2 decds.cast decds.cast.v2
agg decds.cast.v2 decds.gif --speed 1.5
open decds.gif

# We can use ffmpeg to convert GIF to MP4.
ffmpeg -i decds.gif -movflags faststart -pix_fmt yuv420p -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" decds.mp4
open decds.mp4

# We can again use ffmpeg to add a background music to our MP4 video.
# Assuming current working directory has a MP3 file `music.mp3`
ffmpeg -i decds.mp4 -stream_loop -1 -i music.mp3 -c:v copy -c:a aac -map 0:v:0 -map 1:a:0 -shortest decds.with.audio.mp4
open decds.with.audio.mp4
