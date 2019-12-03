import sys
import os
import getopt
import zipfile
from subprocess import Popen, PIPE
import subprocess
import shutil
import json
import plistlib
from nostril import nonsense

class whole_arg:
	inputfile = ""
	outputfile = os.getcwd() + "/output.html"
	scan_outputfile = os.getcwd() + "/scan_output.html"
	permission_outputfile = os.getcwd() + "/permission_output.html"
	binaryfile = ""
	rule_file_path = os.getcwd() +  "/rules/rules.json"
	scan_rule_file_path = os.getcwd() + "/rules/scan_rules.json"
	permission_rule_file = os.getcwd() + "/rules/permission_rules.json"
	tools = ["llvm-dec","llvm-lipo","llvm-slicer","jtool"]
	magic_number_list = [b'\xfe\xed\xfa\xce',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf']
	mach_file_path = os.getcwd() + "/tmp/mach_o_file"
	plist_file_path = os.getcwd() + "/tmp/plist_file"
	all_plist_file_path = []
	tmp_file_path = os.getcwd() + "/tmp"
	thin_file_path = os.getcwd() + "/tmp/thin_file"
	ir_file_path = os.getcwd() + "/tmp/n_ir"
	extract_header_file_path = os.getcwd() + "/tmp/header_file.txt"
	def set_inputfile_name(self, tmp_str):
		self.inputfile = os.getcwd() + "/" + tmp_str


def check_python_version():
	print("start to check python version")
	if sys.version_info.major<3:
		print("python version should > 3")

def get_arg(args, program_arg):
	print("start to get program arg")
	try:
		opts, special_arg = getopt.getopt(args, "hi:",["help","inputfile="])
	except getopt.GetoptError:
		print("setup.py -i <inputfile> ")
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-h","--help"):
			print("setup.py -i <inputfile>")
			sys.exit()
		elif opt in ("-i","--inputfile"):
			program_arg.set_inputfile_name(arg)
	if program_arg.inputfile == "":
		print("no input file of the command")
		sys.exit()


def check_tools(tmp_prog_arg):
	print("start to check tools")
	cur_path = os.getcwd()
	tool_path = cur_path + "/tools"
	if os.path.exists(tool_path)==False:
		print("there is no tools dir in cur path")
		sys.exit()
	tmp_tools = tmp_prog_arg.tools
	tmp_files_list = [] 
	for root, dirs, files in os.walk(tool_path, topdown=False):
		for tmp_file in files:
			tmp_files_list.append(tmp_file)
	for tmp_tool_name in tmp_tools:
		if tmp_tool_name not in tmp_files_list:
			print("tool file "+tmp_tool_name+" does not exist")
			sys.exit()


def check_rules(tmp_prog_arg):
	print("start to check rules")
	if os.path.exists(tmp_prog_arg.rule_file_path) == False:
		print("there is no rules.json file in rule dir")
		sys.exit()
	if os.path.exists(tmp_prog_arg.scan_rule_file_path) == False:
		print("there is no rules.json file in rule dir")
		sys.exit()

def check_tmp(tmp_prog_arg):
	print("start to check tmp ")
	if os.path.exists(tmp_prog_arg.tmp_file_path) == False:
		os.mkdir(tmp_prog_arg.tmp_file_path)


def is_the_main_execute_file(file_name):
	tmp_name_list = file_name.split("/")
	list_size = len(tmp_name_list)
	final_name = tmp_name_list[list_size-1]
	if (final_name + ".app") == tmp_name_list[1]:
		return True
	if (final_name + ".app") == tmp_name_list[2]:
		return True
	if (final_name + ".app") == tmp_name_list[0]:
		return True
	return False


def unzip_inputfile(tmp_prog_arg):
	print("start to unzip input file")
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
	ipa_file.extract(mach_file, path = tmp_prog_arg.tmp_file_path)
	shutil.copy(tmp_prog_arg.tmp_file_path + "/" + mach_file, tmp_prog_arg.mach_file_path)

def unzip_allplistfile(tmp_prog_arg):
	print("start to unzip all plist file")
	if(os.path.exists(tmp_prog_arg.inputfile) == False):
		print("input file does not exists")
		sys.exit()
	if(zipfile.is_zipfile(tmp_prog_arg.inputfile) == False):
		print("input file is not a zip file ")
		sys.exit()
	ipa_file = zipfile.ZipFile(tmp_prog_arg.inputfile)
	name_list = ipa_file.namelist()
	plist_file = []
	for zip_file_name in name_list:
		if zip_file_name.endswith("/Info.plist"):
			plist_file.append(zip_file_name)
	if(len(plist_file)==0):
		print("did not find info.plist")
		sys.exit()
	plist_file_size = 0
	for tmp_plist_file in plist_file:
		print(tmp_plist_file)
		ipa_file.extract(tmp_plist_file, path = tmp_prog_arg.tmp_file_path)
		shutil.copy(tmp_prog_arg.tmp_file_path + "/" + tmp_plist_file, tmp_prog_arg.plist_file_path + str(plist_file_size))
		tmp_prog_arg.all_plist_file_path.append(tmp_prog_arg.plist_file_path + str(plist_file_size))
		plist_file_size = plist_file_size + 1


def lipo_file(tmp_prog_arg):
	print("start to thin mach-o file")
	tools_dir = os.getcwd() + "/tools/llvm-lipo"
	lipo_info_cmd = tools_dir + " -archs " +tmp_prog_arg.mach_file_path
	p = subprocess.Popen(lipo_info_cmd, shell = True, stdout = PIPE, stderr = PIPE)
	p.wait()
	if p.returncode !=0 : 
		print("command : " + lipo_info_cmd + " failed")
		sys.exit()
	std_output = p.stdout.readlines()
	whole_arch_name = bytes.join(b'',std_output).decode('utf-8')
	arch_name_list = whole_arch_name.split(" ")
	if "arm64" not in arch_name_list:
		print("there is no arm64 arch in the mach-o file")
		sys.exit()
	arch_size = 0;
	for tmp_arch_name in arch_name_list:
		if tmp_arch_name == "\n":
			continue
		if tmp_arch_name == "":
			continue 
		arch_size = arch_size + 1
	if arch_size == 1 :
		shutil.copy(tmp_prog_arg.mach_file_path, tmp_prog_arg.thin_file_path)
		return 
	lipo_thin_cmd = tools_dir + " " + tmp_prog_arg.mach_file_path + " -thin arm64 -output " + tmp_prog_arg.thin_file_path
	p = subprocess.Popen(lipo_thin_cmd, shell=True, stdout = PIPE, stderr = PIPE)
	p.wait()
	if p.returncode !=0 :
		print("command : " + lipo_thin_cmd + " failed")
		sys.exit()

def ios_to_ir(tmp_prog_arg):
	print("start to translate arm64 to IR")
	tools_dir = os.getcwd() + "/tools/llvm-dec"
	llvm_dec_cmd = tools_dir + " " + tmp_prog_arg.thin_file_path + " -bc " + " -O1 " + " -o " + tmp_prog_arg.ir_file_path
	p = subprocess.Popen(llvm_dec_cmd, shell = True, stdout = PIPE, stderr = PIPE)
	p.wait()
	if p.returncode !=0 :
		print("command : " + llvm_dec_cmd + " failed")
		sys.exit()

def slice_code(tmp_prog_arg):
	print("start to slice IR to check rules")
	tools_dir = os.getcwd() + "/tools/llvm-slicer"
	llvm_slicer_cmd = tools_dir + " " + tmp_prog_arg.ir_file_path + " -binary " + tmp_prog_arg.thin_file_path + " -o /dev/null " + " -rules " + tmp_prog_arg.rule_file_path + " -r " + tmp_prog_arg.outputfile + " -scan_rules " + tmp_prog_arg.scan_rule_file_path + " -sr " + tmp_prog_arg.scan_outputfile
	p = subprocess.Popen(llvm_slicer_cmd, shell = True, stdout = PIPE, stderr = PIPE)
	p.wait()
	if p.returncode !=0:
		print("command : " + llvm_slicer_cmd + " failed")
		sys.exit()

def delete_tmp_file(tmp_prog_arg):
	print("start to delete tmp file ")
	tmp_path = os.getcwd()+"/tmp"
	shutil.rmtree(tmp_path)
	os.mkdir(tmp_path)

def extract_header_file(tmp_prog_arg):
	print("start to extract header file ")
	tools_dir = os.getcwd() + "/tools/jtool"
	extract_cmd = tools_dir + "  -d objc " + tmp_prog_arg.thin_file_path + " > " + tmp_prog_arg.extract_header_file_path
	p = subprocess.Popen(extract_cmd,shell = True, stdout = PIPE, stderr = PIPE)
	p.wait()
	if (os.path.exists(tmp_prog_arg.extract_header_file_path)==False):
		print("command : " + extract_cmd + " failed")
		sys.exit()

def check_if_obfuscated(tmp_prog_arg):
	print("start to check obfuscated")
	extract_header_file(tmp_prog_arg)
	tmp_header_file = open(tmp_prog_arg.extract_header_file_path)
	tmp_nonsense = 0
	tmp_real = 0 
	for tmp_s in tmp_header_file.readlines():
		#if(tmp_s.find("*/ ")==-1):
		#	continue
		#tmp_s = tmp_s[tmp_s.find("*/ ")+3:]
		#if(tmp_s.find("// ") == -1):
		#	print("header file extract not correct")
		#	sys.exit()
		#tmp_s = tmp_s[:tmp_s.find("// ")]
		if(len(tmp_s)<=6):
			continue
		if nonsense(tmp_s):
			tmp_nonsense = tmp_nonsense + 1
		else:
			tmp_real = tmp_real+1
	if tmp_nonsense + tmp_real == 0 :
		print("didn't find useful name")
		sys.exit()
	tmp_result = float(tmp_real)/ (tmp_nonsense + tmp_real)
	if tmp_result<0.9 :
		print("this application is obfuscated")
		sys.exit()

def print_permission_check_rule(tmp_prog_arg, rule_list):
	permission_result_html = open(tmp_prog_arg.permission_outputfile, "w")
	head = """
	<html>
	<head>
	 <meta charset="utf-8">
        <title>permission is requested</title>
	<link rel="stylesheet" href="scripts/bootstrap.min.css">
	<link rel="stylesheet" href="scripts/report.css">
	<script src="scripts/jquery.min.js"></script>
	<script src="scripts/bootstrap.min.js"></script>
	<script src="scripts/helper.js"></script>
	</head>
	<body>
	"""
	for rule in rule_list:
		head = head + "<div>"
		head = head + "<h1>" + rule["name"] + "</h1>"
		head = head + "<h3>" + rule["description"] + "</h3>"
		head = head + "</div>"
	head = head + """
	</body>
	</html>
	"""
	permission_result_html.write(head)
	permission_result_html.close()

def get_and_check_permissions(tmp_prog_arg):
	permission_rule_file = open(tmp_prog_arg.permission_rule_file)
	rule_list = json.load(permission_rule_file)
	trigger_rule_list = []
	for plist_file_path in tmp_prog_arg.all_plist_file_path:
		#plist_file = open(plist_file_path,"rb")
		#plist_lib = plistlib.loads(plist_file_path)
		plist_file = plistlib.readPlist(plist_file_path)
		for rule in rule_list:
			if(rule["key"] == None):
				print("rule is not correct")
				sys.exit()
			if (rule["key"] not in plist_file.keys()):
				continue
			if(rule["type"] == "any"):
				trigger_rule_list.append(rule)
			if(rule["type"] == "equal"):
				if(plist_file[rule["key"]] == rule["value"]):
					trigger_rule_list.append(rule)
			if(rule["type"] == "not equal"):
				if(plist_file[rule["key"]] != rule["value"]):
					trigger_rule_list.append(rule)
	print_permission_check_rule(tmp_prog_arg, trigger_rule_list)
			#if(rule["key"])





if __name__ == "__main__":
	prog_arg = whole_arg()
	check_python_version()
	get_arg(sys.argv[1:],prog_arg)
	check_tools(prog_arg)
	check_rules(prog_arg)
	check_tmp(prog_arg)
	unzip_inputfile(prog_arg)
	unzip_allplistfile(prog_arg)
	get_and_check_permissions(prog_arg)
	check_if_obfuscated(prog_arg)
	lipo_file(prog_arg)
	ios_to_ir(prog_arg)
	slice_code(prog_arg)
	delete_tmp_file(prog_arg)