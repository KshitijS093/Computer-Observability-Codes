To setup on a system: sudo apt-get update sudo apt-get install bpfcc-tools linux-headers-$(uname -r) You need to run the following codes as sudo python3 programname.py

To get output in a single output file: create .sh file and store all the commands and make that file executable (To make executable : Chmod +x filename.sh) (Commands inside of it: sudo python3 file.py >> output.txt) call the executable file all result gets stored onto a particular output file
