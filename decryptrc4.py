def calculate_data_size(data_address):
    data_size = 5
    start = data_address + 5
    while not (bv.read(start, 1) == b"\x00" and bv.read(start + 1, 1) == b"\x00"):
        if bv.read(start, 1) == b"\x00":
            if bv.get_data_var_at(start + 1) != None:
                break
        data_size += 1
        start += 1
    return data_size

### Define the struct for the decrypt function
def define_struct(name, size):
    bv.define_user_type(
        name,
        bv.parse_types_from_string(f"struct {name} {{ char key[0x28]; char data[{size}];}};").types[name]
    )

data_list = []
struct_list = []
reverse = Transform['Reverse']
RC4 = Transform['RC4']

### Get the RC4 decrypt function from address
rc4_addr = 0x0061e5d0 # decrypt function address
rc4_func = bv.get_function_at(rc4_addr)

log_info(f"[!] Start processing")

### Get the caller sites of the RC4 decrypt function
RC4_caller_sites = [cs for cs in rc4_func.caller_sites]
log_info(f"[!] Found {len(RC4_caller_sites)} caller sites from RC4 decrypt function")

bv.begin_undo_actions()
log_info("[!] Starting to find data addresses")

for cs in RC4_caller_sites:
    data_address = cs.hlil.params[2]
    ## In case the buffer is passed directly to the RC4 decrypt function
    if data_address.operation == HighLevelILOperation.HLIL_CONST:
        data_address = data_address.constant
        key_address  = data_address - 0x28
        data_size    = calculate_data_size(data_address)
        if data_address not in data_list:
            log_info(f"[!] RC4 function: Found data at {hex(data_address)} with size {hex(data_size)}")
            data_list.append(data_address)
            struct_list.append((key_address, data_size))
        else:
            continue

    ## In case the buffer is passed through a wrapper function
    elif data_address.operation == HighLevelILOperation.HLIL_ADD:
        wrapper = bv.get_functions_containing(cs.address)[0] # Get the wrapper function
        wrapper_caller_sites = [wcs for wcs in wrapper.caller_sites]
        log_info(f"[!] Found a wrapper with {len(wrapper_caller_sites)} caller sites")

        for wrapper_cs in wrapper_caller_sites:

            key_address = wrapper_cs.hlil.params[1]

            ### If the address is a constant
            if key_address.operation == HighLevelILOperation.HLIL_CONST or key_address.operation == HighLevelILOperation.HLIL_CONST_PTR:
                key_address = key_address.constant
                data_address  = key_address + 0x28
                data_size    = calculate_data_size(data_address)
                if data_address not in data_list:
                    log_info(f"     [!] Wrapper function: Found data at {hex(data_address)} with size {hex(data_size)}")
                    data_list.append(data_address)     
                    struct_list.append((key_address, data_size))           
                else:
                    continue
            
            ### If the address is a variable and has multiple possible values
            elif key_address.operation == HighLevelILOperation.HLIL_VAR:
                key_possible_list = list(key_address.get_possible_values().values)
                for key_address in key_possible_list:
                    key_address = key_address
                    data_address = key_address + 0x28
                    data_size    = calculate_data_size(data_address)
                    if data_address not in data_list:
                        log_info(f"     [!] Wrapper function: Found data at {hex(data_address)} with size {hex(data_size)}")
                        data_list.append(data_address)
                        struct_list.append((key_address, data_size))
                    else:
                        continue

log_info(f"\n[!] Found {len(struct_list)} data addresses")

for struct_address, data_size in struct_list:
    define_struct(f"RC4_{hex(struct_address)}", data_size)
    bv.define_user_data_var(struct_address, f"RC4_{hex(struct_address)}")

log_info("[!] Defined structs and data vars")

for struct_address, data_size in struct_list:
    var = bv.get_data_var_at(struct_address)
    key_value = reverse.decode(var['key'].value)
    data = var['data']
    dec_data = RC4.decode(data.value, {'key' : key_value})
    data.value = dec_data

log_info("[!] Decrypted data")

bv.commit_undo_actions()
log_info("[!] Finished processing")
