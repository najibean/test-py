import csv, re, random
import logging, argparse
import shutil, os

class color:
    NORMAL = ''
    BLUE = '\033[94m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def log(lvl, col, msg):
        logger.log(lvl, col + msg + color.END)

print(color.BOLD + color.RED + "____  ___              ___________.__                      " + color.END)
print(color.BOLD + color.RED + "\   \/  /  ______ _____\_   _____/|__|__  ___ ___________  " + color.END)
print(color.BOLD + color.RED + " \     /  /  ___//  ___/|    __)  |  \  \/  // __ \_  __ \ " + color.END)
print(color.BOLD + color.RED + " /     \  \___ \ \___ \ |     \   |  |>    <\  ___/|  | \/ " + color.END)
print(color.BOLD + color.RED + "/___/\  \/____  >____  >\___  /   |__/__/\_ \\___  >__|    " + color.END)
print(color.BOLD + color.RED + "      \_/     \/     \/     \/             \/    \/        " + color.END)
print("Author: " + color.BOLD + color.RED + "Vlastimil Novak" + color.END)
print("Read-only Usage: python XssFixer.py -c files_with_vuln.csv")
print("Edit Usage: python XssFixer.py -c files_with_vuln.csv -f")
print("")
print("Description: XssFixer helping provide script tool to quickly resolve XSS issues,")
print("which can be done with help of automation. The rest can be done manually.")

logger = logging.getLogger(__name__)
lh = logging.StreamHandler()  # Handler for the logger
logger.addHandler(lh)
formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
lh.setFormatter(formatter)

parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store', dest='csv_file',
                    help='CSV File with list of files and vulnerable line')
parser.add_argument('-f', action='store_true', dest='fix_mode',
                    help='Enable fixing mode')
parser.add_argument('-r', action='store_true', dest='random_mode',
                    help='Enable random line reading')
parser.add_argument('-v', action='store_true', dest='verbose',
                    help='Enable verbose logging')
results = parser.parse_args()
logger.setLevel(logging.DEBUG if results.verbose else logging.INFO)
fix_mode = results.fix_mode
random_mode = results.random_mode

def fixInFile(vulnerable_file, vulnerable_line_number, fixed_line):
    color.log(logging.DEBUG, color.YELLOW, '[*] Patching ' + vulnerable_file + ':' + str(vulnerable_line_number))
    shutil.move( vulnerable_file, vulnerable_file+"~" )

    destination= open( vulnerable_file, "w" )
    source= open( vulnerable_file+"~", "r" )
    for counter, line in enumerate(source):
        if (counter + 1) == vulnerable_line_number:
            destination.write(fixed_line)
        else:
            destination.write(line)
    source.close()
    destination.close()
    os.remove(vulnerable_file+"~")
    
def fixJavascriptXSS(vulnerable_file, vulnerable_line_number, vulnerable_line):
    color.log(logging.INFO, color.YELLOW, '[*] JavaScript XSS Vulnerability.')
    color.log(logging.INFO, color.RED, vulnerable_line.strip())   
    color.log(logging.INFO, color.GREEN, '[*] Consider implement: https://github.com/leizongmin/js-xss')
    color.log(logging.INFO, color.GREEN, '[*] Consider implement: https://github.com/cure53/DOMPurify')
    color.log(logging.INFO, color.GREEN, "[*] Or just DELETE the code if it isn't important!")

def fixDOMBasedXSS(vulnerable_file, vulnerable_line_number, vulnerable_line):
    color.log(logging.INFO, color.YELLOW, '[*] DOM Based XSS.')
    vulnerable_line_fixed = vulnerable_line.replace('innerHTML','textContent')
    color.log(logging.INFO, color.NORMAL, '---------------------------------------------------------------')
    color.log(logging.INFO, color.RED, vulnerable_line.strip())
    color.log(logging.INFO, color.NORMAL, '---------------------------------------------------------------')
    color.log(logging.INFO, color.GREEN, vulnerable_line_fixed.strip())
    color.log(logging.INFO, color.NORMAL, '---------------------------------------------------------------')
    if fix_mode:
        color.log(logging.INFO, color.BOLD, 'Do you want apply fix? (Y)es, (S)kip, (Q)uit')
        val = input("Enter your value: ")
        if val == 'S' or val == 's':
            return
        elif val == 'Q' or val == 'q':
            exit(0)
        else:
            fixInFile(vulnerable_file, vulnerable_line_number, vulnerable_line_fixed)

def fixBasicXSS(vulnerable_file, vulnerable_line_number, vulnerable_line):
    color.log(logging.INFO, color.YELLOW, '[*] ASP Basic XSS.')
    asp_code_l = re.findall('(<%={0,1}.*?%>)', vulnerable_line)
    asp_code_l = list(dict.fromkeys(asp_code_l))
    fixed_line = vulnerable_line
    fixed_line_no_color = vulnerable_line

    # For <% %> code
    for asp_code in asp_code_l:
        color.log(logging.DEBUG, color.YELLOW, '[*] ASP Code detected: ' + asp_code) 
        vulnerable_line = vulnerable_line.replace(asp_code, color.RED + asp_code + color.END)
        # ASP regex
        asp_expr = re.findall('<%={0,1}(.*?)%>', asp_code)[0].strip()
        # Apply Fix
        # Test for Server.URLEncode()
        if 'Server.URLEncode' in asp_expr:
            asp_expr = re.findall('Server.URLEncode\((.*)\)', asp_expr, re.IGNORECASE)[0].strip()
        #
        asp_code_fixed = asp_code.replace(asp_expr, color.END + color.BLUE + 'Server.HTMLEncode(' + color.END + color.GREEN + asp_expr + color.END + color.BLUE + ' & "")' + color.GREEN)
        asp_code_fixed_no_color = asp_code.replace(asp_expr, 'Server.HTMLEncode(' + asp_expr + ' & "")')
        fixed_line = fixed_line.replace(asp_code, color.GREEN + asp_code_fixed + color.END)
        fixed_line_no_color = fixed_line_no_color.replace(asp_code, asp_code_fixed_no_color)
        # Apply Fix - END

    # For Response.Write code
    # Test for Response.Write
    if 'response.write' in vulnerable_line.lower():
        asp_code = re.findall('Response.Write(.*)', vulnerable_line, re.IGNORECASE)[0].strip()
        vulnerable_line = vulnerable_line.replace(asp_code, color.RED + asp_code + color.END)
        fixed_line = fixed_line.replace(asp_code, color.END + color.BLUE + 'Server.HTMLEncode(' + color.END + color.GREEN + asp_code + color.END + color.BLUE + ' & "")' + color.GREEN)
        fixed_line_no_color = fixed_line_no_color.replace(asp_code, 'Server.HTMLEncode(' + asp_code + ' & "")')
    #

    color.log(logging.INFO, color.NORMAL, '---------------------------------------------------------------')
    color.log(logging.INFO, color.NORMAL, vulnerable_line.strip())
    color.log(logging.INFO, color.NORMAL, '---------------------------------------------------------------')
    color.log(logging.INFO, color.NORMAL, fixed_line.strip())
    color.log(logging.INFO, color.NORMAL, '---------------------------------------------------------------')
    if fix_mode:
        color.log(logging.INFO, color.BOLD, 'Do you want apply fix? (Y)es, (S)kip, (Q)uit')
        val = input("Enter your value: ")
        if val == 'S' or val == 's':
            return
        elif val == 'Q' or val == 'q':
            exit(0)
        else:
            fixInFile(vulnerable_file, vulnerable_line_number, fixed_line_no_color)

def main():
    if not results.csv_file:    # if the url has been passed or not
        color.log(logging.INFO, color.RED, 'CSV File not provided')
        return []

    filepath = results.csv_file
    # Open CSV and read source code with vulnerable file:line
    with open(filepath) as fp:
        reader = csv.reader(fp, delimiter=',')
        reader = list(reader)[1:]
        asp_script_list = ('<%=', '<%', 'response.write')
        for cnt, line in enumerate(reader):
            if random_mode:
                line = random.choice(reader)
            vulnerable_file = line[4][1:] if line[4][0] == '/' else line[4]
            vulnerable_line_number = int(line[3])
            # Open vulnerable source code in AGIA
            agia_source_file = open("./" + vulnerable_file, encoding='cp1250', errors='ignore')
            color.log(logging.INFO, color.BLUE, '[*] Opening ' + vulnerable_file + ':' + str(vulnerable_line_number))
            for a_cnt, a_line in enumerate(agia_source_file):
                vulnerable_line = a_line
                # Find vulnerable line of the code
                if (a_cnt + 1) == vulnerable_line_number:
                    agia_source_file.close()
                    # If fix already applied, skip
                    if 'Server.HTMLEncode' in vulnerable_line:
                        break
                    if all(s not in vulnerable_line.lower() for s in asp_script_list):
                        if 'innerHTML' in vulnerable_line:
                            fixDOMBasedXSS(vulnerable_file, vulnerable_line_number, vulnerable_line)
                        else:
                            fixJavascriptXSS(vulnerable_file, vulnerable_line_number, vulnerable_line)
                    else:
                        fixBasicXSS(vulnerable_file, vulnerable_line_number, vulnerable_line)
                    color.log(logging.INFO, color.BLUE, '')
                    break
            #if cnt == 10:
            #    exit(-1)
if __name__ == '__main__':
    main()