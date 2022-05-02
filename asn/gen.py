from pycrate_asn1c.asnproc import *

asntxt = open('./v2x.asn').read()
compile_text(asntxt)
generate_modules(PycrateGenerator, './v2x.py')