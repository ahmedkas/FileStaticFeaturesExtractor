import sys
sys.path.append(".")
from Utils import *

pathRead = "EXAMPLE-SOFTWARE-BINARY-PATH" # The path to the binaries

# Convert binaries to image representation
img = convert_bin_to_image_height(pathRead,width=64,height=64)
print(img.shape)

# Convert binaries to bytes hexdump representation
hexdump = convert_bin_to_HexDump(pathRead)
print(hexdump.shape)

# Convert binaries to two-bytes hexdump representation
TwoBytesHexdump = convert_bin_to_HexDump2bytes(pathRead)
print(TwoBytesHexdump.shape)

# Convert binaries to two-bytes hexdump hashed representation
TwoBytesHexdump_hashed = convert_bin_to_HexDump2bytes_hashed(pathRead,size=1024)
print(TwoBytesHexdump_hashed.shape)

# Convert binaries to N-bytes hexdump hashed representation
NBytesHexdump = convert_bin_to_HexDumpNbytes_hashed(pathRead,N=3,size=1024)
print(NBytesHexdump.shape)

# Extract strings from binaries
Strings = convert_bin_to_String_Rep(pathRead)
if Strings != None:
    # Hash the strings into a vector representation
    HashStrings = hashing(Strings,size=1024)
    print(HashStrings.shape)

# Extract relocations from binaries
relocs = convert_bin_to_Relocs_Rep(pathRead)
if relocs != None:
    # Hash the relocations into a vector representation
    HashRelocs = hashing(relocs,size=1024)
    print(HashRelocs.shape)

# Extract section names from binaries
sections = convert_bin_to_Sections_Rep(pathRead)
if sections != None:
    # Hash the section names into a vector representation
    HashSections = hashing(sections,size=1024)
    print(HashSections.shape)

# Extract function names from binaries
functions = convert_bin_to_Functions_Rep(pathRead)
if functions != None:
    # Hash the function names into a vector representation
    HashFunctions = hashing(functions,size=1024)
    print(HashFunctions.shape)

# Extract imported resources names from binaries
imports = convert_bin_to_Imports_Rep(pathRead)
if imports != None:
    # Hash the imported resources names into a vector representation
    HashImports = hashing(imports,size=1024)
    print(HashImports.shape)
