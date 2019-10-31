import sys
import os
import getopt
import zipfile
from subprocess import Popen, PIPE
import subprocess

class whole_arg:
	inputfile = ""
	outputfile = ""
	binaryfile = ""
	tools = ["llvm-dec","llvm-lipo","llvm-slicer"]
	magic_number_list = [b'\xfe\xed\xfa\xce',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf']
	mach_file_path = os.getcwd()+"/tmp/mach_o_file"
	thin_file_path = os.getcwd()+"/tmp/thin_file"
	def set_inputfile_name(self, tmp_str):
		self.inputfile = tmp_str
	def set_outputfile_name(self, tmp_str):
		self.outputfile = tmp_str
	def set_binaryfile_name(self, tmp_str):
		self.binaryfile = tmp_str


def check_python_version():
	if sys.version_info.major<3:
		print("python version should > 3")

def get_arg(args, program_arg):
	try:
		opts, special_arg = getopt.getopt(args, "hi:o:",["help","inputfile=","outputfile="])
	except getopt.GetoptError:
		print("setup.py -i <inputfile> -o <outputfile>")
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-h","--help"):
			print("setup.py -i <inputfile> -o <outputfile>")
			sys.exit()
		elif opt in ("-i","--inputfile"):
			program_arg.set_inputfile_name(arg)
		elif opt in ("-o","--outputfile"):
			program_arg.set_outputfile_name(arg)

def check_tools(tmp_prog_arg):
	cur_path = os.getcwd()
	tool_path = ""
	for root, dirs, files in os.walk(cur_path,topdown=False):
		if(dirs == "tools"):
			tool_path = root + dirs
	if tool_path == "":
		print("there is no tools dir in cur path")
		sys.exit()
	tmp_tools = tmp_prog_arg.tools
	tmp_files_list = [] 
	for root, dirs, files in os.walk(tool_path, topdown=False):
		tmp_files_list.append(files)
	for tmp_tool_name in tmp_tools:
		if tmp_tool_name not in tmp_files_list:
			print("tool file "+tmp_tool_name+" does not exist")
			sys.exit()
def check_rules(tmp_prog_arg):
	cur_path = os.getcwd()
	rule_path = ""
	for root, dirs, files in os.walk(cur_path, topdown=False):
		if(dirs == tools)

def is_the_main_execute_file(file_name):
	tmp_name_list = file_name.split("/")


def unzip_inputfile(tmp_prog_arg):
	if(os.path.exists(tmp_prog_arg.inputfile) == False):
		print("input file does not exists")
		sys.exit()
	if(zipfile.is_zipfile(tmp_prog_arg.inputfile) == False):
		print("input file is not a zip file ")
		sys.exit()
	ipa_file = zipfile.ZipFile(tmp_prog_arg.inputfile)
	name_list = ipa_file.namelist()
	mach_file = ""
	for zip_file_name in name_list:
		with ipa_file.open(zip_file_name) as tmp_zip_file:
			tmp_result = tmp_zip_file.read()[0:4]
			if(tmp_result in tmp_prog_arg.magic_number_list):
				if(is_the_main_execute_file(zip_file_name)==True):
					mach_file = zip_file_name
	if(mach_file == ""):
		print("no executable mach-o file")
		sys.exit()
	ipa_file.extract(mach_file, path = tmp_prog_arg.mach_file_path)

def lipo_file(tmp_prog_arg):
	tools_dir = os.getcwd() + "/tools/llvm-lipo"
	lipo_info_cmd = tools_dir + " -info " +tmp_prog_arg.mach_file_path
	p = subprocess.Popen(lipo_info_cmd, shell = True, stdout = PIPE, stderr = PIPE)
	p.wait()
	if p.returncode !=0 : 
		print("llvm-lipo execute failed")
		sys.exit()
	std_output = p.stdout
	#print(std_output)
	if "arm64" not in std_output:
		print("there is no Arm64 arch in the mach-o file")
		sys.exit()
	if "Non-fat" in std_output:
		tmp_prog_arg.thin_file_path = tmp_prog_arg.mach_file_path
		return 
	lipo_thin_cmd = tools_dir + " " + tmp_prog_arg.mach_file_path + " -thin arm64" + 






if __name__ == "__main__":
	prog_arg = whole_arg()
	check_python_version()
	get_arg(sys.argv[1:],prog_arg)
	check_tools(prog_arg)
	unzip_inputfile(prog_arg)
	lipo_file(prog_arg)