"""Sequential native attachment cases; stop on first failed oracle or collector."""
import subprocess,sys
candidate='target/continuation-20261027T185926Z/candidate.json'
platform=sys.argv[1]
assert platform in ('debian-arm64','arch-x86_64','debian-x86_64')
prefix={'debian-arm64':'arm64','arch-x86_64':'arch','debian-x86_64':'amd64-old'}[platform]
for mode in ('success','placeholder-failure','publication-failure'):
 label=prefix+'-secret-attachment-pollfix-'+mode
 subprocess.run([sys.executable,'target/platform-lab/run-frozen-secret-attachment.py',candidate,platform,label,mode],check=True)
 subprocess.run([sys.executable,'target/collect-secret-attachment.py',candidate,label],check=True)
