import os
import sys
import clr
import pefile

# Add dnlib reference
dnlib_dll_path = os.path.join(os.path.dirname(__file__), "dnlib")
clr.AddReference(dnlib_dll_path)

# Import dnlib modules
import dnlib
from dnlib.DotNet import ModuleDef, ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from dnlib.DotNet.Writer import ModuleWriterOptions

# Import reflection modules
from System import Int32
from System.Reflection import Assembly, BindingFlags, MethodInfo

class StringDecryptor:
    # Target decryption functions to invoke
    DECRYPTION_METHOD_SIGNATURES = [
        {
            "Parameters": ["System.Int32"],
            "ReturnType": "System.String"
        },
        {
            "Parameters": ["System.Int32"],
            "ReturnType": "System.Object"
        },
        {
            "Parameters": ["System.String", "System.Int32"],
            "ReturnType": "System.String"
        },
        {
            "Parameters": ["System.String", "System.String"],
            "ReturnType": "System.String"
        },
    ]

    def __init__(self, file_path) -> None:
        self.file_path: str = file_path
        self.file_module: ModuleDefMD = ModuleDefMD.Load(file_path)
        self.file_assembly: Assembly = Assembly.LoadFile(file_path)

        # Suspected methods and their corresponding signatures and invoke methods
        self.suspected_methods: dict[ModuleDef, tuple[str, MethodInfo]] = {}
        # Decrypted strings
        self.decrypted_strings: list[str] = []


    # Map suspected method names to their corresponding signatures and MethodInfo objects
    def IdentifySuspectedMethods(self):
        # Search for static, public and non public members
        eFlags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic

        for module_type in self.file_assembly.GetTypes():
            for method in module_type.GetMethods(eFlags):
                # Check if the current method has a suspected signature
                for sig in StringDecryptor.DECRYPTION_METHOD_SIGNATURES:
                    # Check number of parameters and return type
                    parameters = method.GetParameters()
                    if ((len(parameters) == len(sig["Parameters"])) and
                        (method.ReturnType.FullName == sig["ReturnType"])):

                        # Check parameters types
                        param_types_match = True
                        for i in range(len(parameters)):
                            if parameters[i].ParameterType.FullName != sig["Parameters"][i]:
                                param_types_match = False
                                break

                        if param_types_match:
                            # Store the signature and MethodInfo object of the current method
                            method_name = f"{method.DeclaringType.FullName}::{method.Name}"
                            self.suspected_methods[method_name] = (sig, method)


    # Get instruction's operand value
    def GetOperandValue(self, insn, paramType):
        if "Int32" in paramType:
            if insn.IsLdcI4():
                return Int32(insn.GetLdcI4Value())
        elif "String" in paramType:
            if insn.OpCode == OpCodes.Ldstr:
                return insn.Operand
        else:
            return None


    # Invoke all references to suspected methods
    def DecryptStrings(self):
        for module_type in self.file_module.Types:
            if not module_type.HasMethods:
                continue

            for method in module_type.Methods:
                if not method.HasBody:
                    continue

                # Loop through method instructions
                for insnIdx, insn in enumerate(method.Body.Instructions):
                    # Find Call instructions
                    if insn.OpCode == OpCodes.Call:
                        for s_method_name, (s_method_sig, s_method_info) in self.suspected_methods.items():
                            # Check if the callee is one of the suspected methods
                            if str(s_method_name) in str(insn.Operand):
                                # Get method parameters in reverse order
                                params = []
                                for i in range(len(s_method_sig["Parameters"])):
                                    operand = self.GetOperandValue(
                                        method.Body.Instructions[insnIdx - i - 1],
                                        s_method_sig["Parameters"][-i - 1])
                                    if operand is not None:
                                        params.append(operand)

                                # Check if we got all the parameters
                                if len(params) == len(s_method_sig["Parameters"]):
                                    # Invoke suspected method
                                    try:
                                        result = str(s_method_info.Invoke(None, params[::-1]))
                                    except Exception as e:
                                        continue

                                    # Patch suspected method parameters with NOPs
                                    for i in range(len(s_method_sig["Parameters"])):
                                        method.Body.Instructions[insnIdx - i - 1].OpCode = OpCodes.Nop

                                    # Patch suspected method call with the result string
                                    method.Body.Instructions[insnIdx].OpCode = OpCodes.Ldstr
                                    method.Body.Instructions[insnIdx].Operand = result
                                    self.decrypted_strings.append(result)

    # Save the cleaned module to disk
    def SaveModule(self):
        # Add writer options to ignore dnlib errors
        options = ModuleWriterOptions(self.file_module)
        options.Logger = dnlib.DotNet.DummyLogger.NoThrowInstance

        # Build cleaned file name
        split_name = self.file_path.rsplit(".", 1)
        if len(split_name) == 1:
            cleaned_filename = "{0}_cleaned".format(*split_name)
        else:
            cleaned_filename = "{0}_cleaned.{1}".format(*split_name)

        # Write cleaned module content
        self.file_module.Write(cleaned_filename, options)


def main():
    if len(sys.argv) < 2:
        sys.exit("[!] Usage: dotnet_string_decryptor.py <dotnet_file_path>")

    file_path = sys.argv[1]

    # Check if the file exists
    if not os.path.exists(file_path):
        sys.exit("[-] File not found")

    # Use absolute file path
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    # Check if the file is a valid PE
    try:
        pe = pefile.PE(file_path)
    except:
        sys.exit("[-] Invalid PE file")

    # Check if the file is .NET
    dotnet_dir = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'] # COM descriptor table index
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_dir].VirtualAddress == 0:
        sys.exit("[-] File is not .NET")

    decryptor = StringDecryptor(file_path)
    decryptor.IdentifySuspectedMethods()

    # Print suspected decryption method names
    for method_name in decryptor.suspected_methods.keys():
        print(f"[+] Suspected decryption method: {method_name}")

    decryptor.DecryptStrings()
    decryptor.SaveModule()

    # Print decrypted strings list
    print("\n".join(decryptor.decrypted_strings))


if __name__ == "__main__":
	main()
