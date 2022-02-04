import subprocess as sp, argparse, os, json, requests


class VolatilityAutomation:
    """
    Class to make automation of volatility3 seamless for the user
    They only need to point this script to the correct image and
    directory where volatility3 resides and it will do the rest
    Output is saved to [HOME]/voltomation.
    Use as follows:
    python3 vol3_automation.py -f [path_to]/Image.mem -v [path_with_vol.py]/volatility3
    """
    def __init__(self, vol: str, image: str, profile: str) -> None:
        vol = vol.rstrip('/')
        self.vol = vol
        self.image = image
        self.profile = profile

    def find_correct_symbol_table(self) -> bool:
        """
        Function designed to find download and save the correct profile/symbols table for the image
        """
        try:
            # Get kernel version
            print("Getting profile")
            if self.profile == 'y':
                kernel_ver = sp.getoutput("uname -r")
            elif self.profile == 'n':
                kernel_ver = (sp.getoutput(f"python3 {self.vol}/vol.py -f {self.image} banners.Banners").split('\t')[2]).split(' ')[2]
            else:
                print('Error')
                return False

            print(f"Profile found: {kernel_ver}")

            # Get a list of all linux profile and find ours
            all_profiles = json.loads(requests.get(
                'https://volatility3-symbols.s3.eu-west-1.amazonaws.com/banners.json').text)
            linux = all_profiles.get('linux', '')
            for url in linux.values():
                if kernel_ver in url[0]:
                    profile = url[0]

            # Download correct symbols to the correct path
            sp.getoutput(f"wget -P {self.vol}/volatility3/framework/symbols/linux/ {profile}")

            print(f"Added the correct profile to {self.vol}/volatility3/symbols/")
            return True

        except Exception as err:
            print(f"Error: {err}")
            return False

    def run_vol_against_image(self):

        """
        Automate running all of the volatility commands against the image
        and add a line at the tope of the file about what is in it
        """

        storage_dir = f"{os.environ['HOME']}/voltomation"

        try:
            
            # Make folder
            print(f"Making directory to store evidence: {storage_dir}")
            sp.run([f"mkdir",  storage_dir])
        
        except Exception as err:
            print(f"Error creating directory: {err}")
            return False

        try:

            # Run commands and save to home directory under "voltomation" folder
            print("Getting bash command history...")
            sp.getoutput(
                f"echo 'Recovers bash command history from memory' > {storage_dir}/bash.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.bash.Bash >> {storage_dir}/bash.txt"
            )
            
            print("Verifying function pointers for network protocols...")
            sp.getoutput(
                f"echo 'Verifies the operation function pointers of network protocols' > {storage_dir}/check_afinfo.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.check_afinfo.Check_afinfo >> {storage_dir}/check_afinfo.txt"
            )
            
            print("Checking processes for shared creds...")
            sp.getoutput(
                f"echo 'Checks if any processes are sharing credential structures' > {storage_dir}/check_creds.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.check_creds.Check_creds >> {storage_dir}/check_creds.txt"
            )
            
            print("Checking if IDT was altered...")
            sp.getoutput(
                f"echo 'Checks if the IDT has been altered' > {storage_dir}/check_idt.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.check_idt.Check_idt >> {storage_dir}/check_idt.txt"
            )
            
            print("Getting module list to sysfs info...")
            sp.getoutput(
                f"echo 'Compares module list to sysfs info, if available' > {storage_dir}/check_modules.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.check_modules.Check_modules >> {storage_dir}/check_modules.txt")
            
            print("Checking system call table for hooks...")
            sp.getoutput(
                f"echo 'Check system call table for hooks' > {storage_dir}/check_syscall.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.check_syscall.Check_syscall >> {storage_dir}/check_syscall.txt"
                )
            
            print("Getting all mapped ELF files for all processes...")
            sp.getoutput(
                f"echo 'Lists all memory mapped ELF files for all processes' > {storage_dir}/elfs.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.elfs.Elfs >> {storage_dir}/elfs.txt"
                )
            
            print("Getting keyboard notifier call chain...")
            sp.getoutput(
                f"echo 'Parses the keyboard notifier call chain' > {storage_dir}/keyboard_notifiers.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.keyboard_notifiers.Keyboard_notifiers >> {storage_dir}/keyboard_notifiers.txt"
                )
            
            print("Getting kernel log buffer...")
            sp.getoutput(
                f"echo 'Kernel log buffer reader' > {storage_dir}/kmsg.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.kmsg.Kmsg >> {storage_dir}/kmsg.txt"
                )
            
            print("Getting loaded kernel modules...")
            sp.getoutput(
                f"echo 'Lists loaded kernel modules' > {storage_dir}/lsmod.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.lsmod.Lsmod >> {storage_dir}/lsmod.txt"
                )
            
            print("Getting memory maps for all processes (lsof)...")
            sp.getoutput(
                f"echo 'Lists all memory maps for all processes' > {storage_dir}/lsof.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.lsof.Lsof >> {storage_dir}/lsof.txt"
                )
            
            print("Getting memory ranges for potential code injection...")
            sp.getoutput(
                f"echo 'Lists process memory ranges that potentially contain injected code' > {storage_dir}/malfind.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.malfind.Malfind >> {storage_dir}/malfind.txt"
                )
            
            print("Getting memory maps for all processes (maps)...")
            sp.getoutput(
                f"echo 'Lists all memory maps for all processes' > {storage_dir}/maps.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.proc.Maps >> {storage_dir}/maps.txt"
                )
            
            print("Getting all processes in memory image...")
            sp.getoutput(
                f"echo 'Lists the processes present in a particular linux memory image' > {storage_dir}/pslist.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.pslist.PsList >> {storage_dir}/pslist.txt"
                )
                        
            print("Getting tree of processes in memory image...")
            sp.getoutput(
                f"echo 'Plugin for listing processes in a tree based on their parent process ID' > {storage_dir}/pstree.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.pstree.PsTree >> {storage_dir}/pstree.txt"
                )
            
            print("Checking tty for hooks...")
            sp.getoutput(
                f"echo 'Checks tty devices for hooks' > {storage_dir}/tty_check.txt && "
                f"python3 {self.vol}/vol.py -f {self.image} linux.tty_check.tty_check >> {storage_dir}/tty_check.txt"
                )
            
            print('Done!')
            return True

        except Exception as err:
            print(f"Error running volatility: {err}")
            return False

    def main(self):
        # This triggers the profile discovery/download and subsequent processing
        try:
            if self.find_correct_symbol_table():
                return self.run_vol_against_image()
        
        except Exception as err:
            print(f"Error running command: {err}")
            return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Takes a linux memory image and automate volatility3 to run against it")
    parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        metavar="FILENAME",
        help="Absolute path to the memory image",
        required=True
    )

    parser.add_argument(
        "-v",
        "--vol",
        dest="volpath",
        metavar="VOLPATH",
        help="Absolute path for directory holding volatility3's 'vol.py'",
        required=True
    )

    parser.add_argument(
        "-p",
        "--profile",
        dest="profile",
        metavar="PROFILE",
        help="Is the profile the same as the host OS? ('y' or 'n')",
        choices=['y','n'],
        required=True
    )

    args = parser.parse_args()

    VOLATILITY = args.volpath
    source_image = args.filename
    profile = args.profile
    vol_aut = VolatilityAutomation(vol=VOLATILITY, image=source_image, profile=profile)
    vol_aut.main()
