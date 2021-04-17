import argparse
import os
import pdb
import sys

parser=argparse.ArgumentParser()
parser.add_argument("file",help="path of PE file")
parser.add_argument('--In',help="使用该参数则输出导入库的信息",action="store_true")
parser.add_argument('--Out',help="使用该参数则输出导出库的信息",action="store_true")
args=parser.parse_args()

###############################################
#处理小端存储
def Little_Endian(s):
    t=''
    l=len(s)
    for x in range(l//2):
        t+=s[l-2*x-2:l-2*x]
    return t


#如果是PE文件则返回1，否则返回e_lfanew
def Dos_Header(b):
    e_magic = b[0:4]
    if e_magic != "4D5A":
        return 0
    e_lfanew = Little_Endian(b[-8:])

    print("="*20,"IMAGE_DOS_HEADER","="*20,sep = "")
    print("MZ标识(WORD)".ljust(25),"e_magic:".ljust(21),"5A4D",sep = "")
    print("PE偏移量(DWORD)".ljust(24),"e_lfanew".ljust(21),e_lfanew,sep="",end="\n\n\n")
    return int(e_lfanew,base=16)


def Nt_Header(b):
    print("="*20,"IMAGE_NT_HEADER","="*21,sep = "")
    print("PE标识(DWORD)".ljust(25),"Signature:".ljust(21),Little_Endian(b),sep="",end="\n\n\n")

#返回(Size of optional header,Number of Sections)
def File_Header(b):
    Machine=Little_Endian(b[0:4])
    NumberOfSection=int(Little_Endian(b[4:8]),base=16)
    Characteristics=Little_Endian(b[-4:])
    SizeOfOptionalHeader=int(Little_Endian(b[-8:-4]),base=16)

    print("="*20,"IMAGE_FILE_HEADER","="*19,sep="")
    print("运行平台(WORD)".ljust(23),"Machine:".ljust(21),Machine,sep="")
    print("节的数量(WORD)".ljust(23),"NumberOfSection:".ljust(21),NumberOfSection,sep="")
    print('文件属性(WORD)'.ljust(23),"Characteristics:".ljust(21),Characteristics,sep="",end="\n\n\n")

    return (SizeOfOptionalHeader,NumberOfSection)


#返回(SectionAlignment,FileAlignment,Export_table,Import_table)
def Optional_Header32(b):
    AddressOfEntryPoint=Little_Endian(b[32:40])
    BaseOfCode=Little_Endian(b[40:48])
    BaseOfData=Little_Endian(b[48:56])
    ImageBase=Little_Endian(b[56:64])
    NumberOfRvaAndSizes=int(Little_Endian(b[0xb8:0xb8+8]),base=16)

    print("="*20,"IMAGE_OPTIONAL_HEADER","="*19,sep="")
    print("程序执行入口(DWORD)".ljust(21),"AddressOfEntryPoint:".ljust(21),AddressOfEntryPoint,sep="")
    print("代码节起始点(DWORD)".ljust(21),"BaseOfCode:".ljust(21),BaseOfCode,sep="")
    print("数据节起始点(DWORD)".ljust(21),"BaseOfData:".ljust(21),BaseOfData,sep="")
    print("建议装入基地址(DWORD)".ljust(20),"ImageBase".ljust(21),ImageBase,sep="")
    print("数据目录数量(DWORD)".ljust(21),"NumberOfRvaAndSizes:".ljust(21),NumberOfRvaAndSizes,sep="",end="\n\n\n")

    Export_table=(Little_Endian(b[192:200]),Little_Endian(b[200:208]))
    Import_table=(Little_Endian(b[208:216]),Little_Endian(b[216:224]))
    TLS_table=(Little_Endian(b[336:344]),Little_Endian(b[344:352]))
    print('='*20,'IMAGE_DATA_DIRECTORY','='*19,sep='')
    print('EXPORT Table:\n','数据起始点(DWORD)'.ljust(21),'VirtualAddress:'.ljust(21),Export_table[0],'\n',\
        '数据块长度(DWORD)'.ljust(21),'Size:'.ljust(21),Export_table[1],sep='',end='\n\n\n')
    print('IMPORT Table:\n','数据起始点(DWORD)'.ljust(21),'VirtualAddress:'.ljust(21),Import_table[0],'\n',\
        '数据块长度(DWORD)'.ljust(21),'Size:'.ljust(21),Import_table[1],sep='',end='\n\n\n')
    print("TLS Table:\n",'数据起始点(DWORD)'.ljust(21),'VirtualAddress:'.ljust(21),TLS_table[0],'\n',\
        '数据块长度(DWORD)'.ljust(21),'Size:'.ljust(21),TLS_table[1],sep='',end='\n\n\n')

    SectionAlignment=Little_Endian(b[64:72])
    FileAlignment=Little_Endian(b[72:80])
    return (SectionAlignment,FileAlignment,Export_table,Import_table)

#返回(SectionAlignment,FileAlignment,Export_table,Import_table)
def Optional_Header64(b):
    AddressOfEntryPoint=Little_Endian(b[32:40])
    BaseOfCode=Little_Endian(b[40:48])
    ImageBase=Little_Endian(b[48:64])
    NumberOfRvaAndSizes=int(Little_Endian(b[0xd8:0xd8+8]),base=16)
    print("="*20,"IMAGE_OPTIONAL_HEADER","="*19,sep="")
    print("程序执行入口(DWORD)".ljust(21),"AddressOfEntryPoint:".ljust(21),AddressOfEntryPoint,sep="")
    print("代码节起始点(DWORD)".ljust(21),"BaseOfCode:".ljust(21),BaseOfCode,sep="")
    print("建议装入基地址(DWORD)".ljust(20),"ImageBase".ljust(21),ImageBase,sep="")
    print("数据目录数量(DWORD)".ljust(21),"NumberOfRvaAndSizes:".ljust(21),NumberOfRvaAndSizes,sep="",end="\n\n\n")
    
    Export_table=(Little_Endian(b[224:232]),Little_Endian(b[232:240]))
    Import_table=(Little_Endian(b[240:248]),Little_Endian(b[248:256]))
    TLS_table=(Little_Endian(b[368:376]),Little_Endian(b[376:384]))
    print('='*20,'IMAGE_DATA_DIRECTORY','='*19,sep='')
    print('EXPORT Table:\n','数据起始点(DWORD)'.ljust(21),'VirtualAddress:'.ljust(21),Export_table[0],'\n',\
        '数据块长度(DWORD)'.ljust(21),'Size:'.ljust(21),Export_table[1],sep='',end='\n\n\n')
    print('IMPORT Table:\n','数据起始点(DWORD)'.ljust(21),'VirtualAddress:'.ljust(21),Import_table[0],'\n',\
        '数据块长度(DWORD)'.ljust(21),'Size:'.ljust(21),Import_table[1],sep='',end='\n\n\n')
    print("TLS Table:\n",'数据起始点(DWORD)'.ljust(21),'VirtualAddress:'.ljust(21),TLS_table[0],'\n',\
        '数据块长度(DWORD)'.ljust(21),'Size:'.ljust(21),TLS_table[1],sep='',end='\n\n\n')
    

    SectionAlignment=Little_Endian(b[64:72])
    FileAlignment=Little_Endian(b[72:80])
    return (SectionAlignment,FileAlignment,Export_table,Import_table)


def Byte_to_Str(b):
    t=''
    l=len(b)//2
    for i in range(l):
        t+=chr(int(b[i*2:i*2+2],base=16))
    return t 


#返回(PointerToRawData,SizeOfRawData)
def Section_Header(b):
    Name=Byte_to_Str(b[:16])       #注意：Name不是小段存储的，不要使用Little_Endian
    VirtualSize=Little_Endian(b[16:24])
    RVA=Little_Endian(b[24:32])
    SizeOfRawData=Little_Endian(b[32:40])
    PointerToRawData=Little_Endian(b[40:48])
    Characteristics=Little_Endian(b[-8:])
    print("节区名称(BYTE)".ljust(24),"NAME:".ljust(19),Name,sep='')
    print("没对齐前真实长度(DWORD)".ljust(20),"VirtualSize:".ljust(19),VirtualSize,sep='')
    print('节的RVA(DWORD)'.ljust(26),'VitualAddress:'.ljust(19),RVA,sep='')
    print('文件中对齐后长度(DWORD)'.ljust(20),"SizeOfRawData:".ljust(19),SizeOfRawData,sep='')
    print("在文件中的偏移(DWORD)".ljust(21),"PointerToRawData:".ljust(19),PointerToRawData,sep='')
    print("节的属性(DWORD)".ljust(24),"Characteristics:".ljust(19),Characteristics,sep='',end='\n\n\n')
    return (Name,PointerToRawData,RVA,VirtualSize)



###########################################
#转换RVA地址为文件偏移地址
def RVA_to_RAW(RVA,VirtualAddress,PointerToRawData):
    rva=int(RVA,base=16)
    vir=int(VirtualAddress,base=16)
    poi=int(PointerToRawData,base=16)
    return rva-vir+poi
#判断导入导出表在哪个节区
def Section_deter(RVA,section_header):
    s=list(section_header.items())
    n=int(RVA,base=16)
    #pdb.set_trace()
    for x in s:
        a=int(x[1][1],base=16)
        b=int(x[1][2],base=16)
        if n>=a and n<=(a+b):
            return x[0]
#判断INT中的数据是ordinal（无名）(返回1）还是函数名称（返回0）
def Ordi(b):
    a=int(b,base=16)
    b=int(section_header[Target_Section][1],base=16)
    c=b+int(section_header[Target_Section][2],base=16)
    if a>=b and a<=c:
        return 0
    else :
        return 1


#由RVA获取库名以及函数名
def Get_Name(RVA):
    #pdb.set_trace()
    s=''
    RAW=RVA_to_RAW(RVA,section_header[Target_Section][1],\
                section_header[Target_Section][0])
    PE.seek(RAW)
    t=PE.read(1).hex().upper()
    while t!='00':
        s+=chr(int(t,base=16))
        t=PE.read(1).hex().upper()
    PE.seek(0)
    return s

#接收INT地址，返回函数名称的列表
def INT_Interpret(OriginalFirstThunk):
    #pdb.set_trace()
    l=[]
    RAW=RVA_to_RAW(OriginalFirstThunk,section_header[Target_Section][1],\
                section_header[Target_Section][0])
    PE.seek(RAW)
    t=Little_Endian(PE.read(4).hex().upper())
    while t!='00000000':
        if Ordi(t):
            l.append("Ordinal")    #使用ordinal来导入函数，没有函数名称
        else:
            t=hex(int(t,base=16)+2)  #跳过hint
            l.append(Get_Name(t))
        RAW+=4
        PE.seek(RAW)
        t=Little_Endian(PE.read(4).hex().upper())
    PE.seek(0)
    return l

#接收IAT地址，返回函数起始地址的列表
def IAT_Interpret(FirstThunk):
    l=[]
    RAW=RVA_to_RAW(FirstThunk,section_header[Target_Section][1],\
                section_header[Target_Section][0])
    PE.seek(RAW)
    t=Little_Endian(PE.read(4).hex().upper())
    while t!="00000000":
        l.append(t)
        t=Little_Endian(PE.read(4).hex().upper())
    PE.seek(0)
    return l

#导入一个库的信息
def Import_dll(b):
    OriginalFirstThunk=Little_Endian(b[:8])
    TimeDateStamp=Little_Endian(b[8:16])
    ForwarderChain=Little_Endian(b[16:24])
    Name_RVA=Little_Endian(b[24:32])
    FirstThunk=Little_Endian(b[32:40])
    #pdb.set_trace()
    Name=Get_Name(Name_RVA)
    fun_name_list=INT_Interpret(OriginalFirstThunk)
    fun_rva_list=IAT_Interpret(FirstThunk)
    print("导入库:{}".format(Name))
    print('='*20)
    print("OriginalFirstThunk".ljust(23),OriginalFirstThunk)
    print("TimeDateStamp".ljust(23),TimeDateStamp)
    print("ForwarderChain".ljust(23),ForwarderChain)
    print("NameRva".ljust(23),Name_RVA)
    print("FirstThunk".ljust(23),FirstThunk)
    print('='*20)
    l=len(fun_name_list)
    for i in range(l):
        print("{}".format(fun_rva_list[i]).ljust(23),fun_name_list[i])
    print('\n\n\n')
    #pdb.set_trace()

    
#解析输入表，结束时将PE的stream position置为0
def Import_Table(Raw,Size):
    PE.seek(Raw)
    b=PE.read(Size).hex().upper()
    l=len(b)//40
    for i in range(l-1):    #减1是因为最后一个是NULL结构
        Import_dll(b[i*40:i*40+40])
    PE.seek(0)



#遍历输出函数名称表
def Export_Func(a,b,c,NumOfName):
    AddressOfNames=RVA_to_RAW(a,section_header[Target_Section][1],\
                section_header[Target_Section][0])
    AddressOfNameOrdinals=RVA_to_RAW(b,section_header[Target_Section][1],\
                section_header[Target_Section][0])
    AddressOfFunctions=RVA_to_RAW(c,section_header[Target_Section][1],\
                section_header[Target_Section][0])
    name_list=[]
    rva_list=[]
    #pdb.set_trace()
    for i in range(NumOfName):
        PE.seek(AddressOfNames+i*4)
        t=Little_Endian(PE.read(4).hex().upper())
        name_list.append(Get_Name(t))
        PE.seek(AddressOfNameOrdinals+i*2)
        ordinal=int(Little_Endian(PE.read(2).hex().upper()),base=16)
        PE.seek(AddressOfFunctions+ordinal*4)
        rva_list.append(Little_Endian(PE.read(4).hex().upper()))
    return (name_list,rva_list)


#解析输出表，结束时将PE的stream position置为0
def Export_Table(Raw):
    PE.seek(Raw)
    b=PE.read(40).hex().upper()
    #Characteristics=Little_Endian(b[:8])
    #TimeDateStamp=Little_Endian(b[8:16])
    Name_RVA=Little_Endian(b[24:32])
    #NumOfFun=int(Little_Endian(b[40:48]),base=16)
    NumOfName=int(Little_Endian(b[48:56]),base=16)
    AddressOfFunctions=Little_Endian(b[56:64])
    AddressOfNames=Little_Endian(b[64:72])
    AddressOfNameOrdinals=Little_Endian(b[72:80])

    Name=Get_Name(Name_RVA)
    (name_list,rva_list)=Export_Func(AddressOfNames,AddressOfNameOrdinals,AddressOfFunctions,NumOfName)
    #pdb.set_trace()

    print('导出库{}'.format(Name))
    print("="*20)
    print("函数名".ljust(37),"函数起始地址")
    for i in range(NumOfName):
        print('{}'.format(name_list[i]).ljust(40),rva_list[i])
    print("="*20+'\n\n\n')



if __name__ == "__main__":
    with open(args.file,'rb') as PE:
        print("File Name:{}".format(os.path.basename(args.file)))

        dos_header=PE.read(0x40).hex().upper()
        e_lfanew=Dos_Header(dos_header)
        if not e_lfanew: 
            print("this file is not in PE format")
            sys.exit()

        PE.seek(e_lfanew)
        nt_header=PE.read(4).hex().upper()
        Nt_Header(nt_header)

        file_header = PE.read(20).hex().upper()
        SizeOfOptionalHeader,NumberOfSection = File_Header(file_header)
        
        optional_header=PE.read(SizeOfOptionalHeader).hex().upper()
        if SizeOfOptionalHeader==0xe0:
            (SectionAlignment,FileAlignment,Export_table,Import_table)=Optional_Header32(optional_header)
        else :
            (SectionAlignment,FileAlignment,Export_table,Import_table)=Optional_Header64(optional_header)
        
        print("="*20,"IMAGE_SECTION_HEADER","="*19,'\n','节的属性参考:',sep='')
        print('''
00000020h	[IMAGE_SCN_CNT_CODE]			Section contains code.(包含可执行代码)
00000040h	[IMAGE_SCN_CNT_INITIALIZED一DATA]	Section contains initialized data.(该块包含己初始化的数据）
00000080h	[IMAGE_SCN_CNT_UNINITIALIZED一DATA] 	Section contains uninitialized data.(该块包含未初始化的数据）
00000200h	[IMAGE_SCN_LNK_INFO]			Section contains comments or some other type of information.
00000800h	[IMAGE_SCN_LNK_REMOVE]			Section contents will not become part of image.
00001000h	[IMAGE_SCN_LNK_COMDAT]			Section contents comdat.
00004000h	[IMAGE_SCN_NO_DEFER_SPEC_EXC]		Reset speculative exceptions handling bits in the TLB entries for this section.
00008000h	[IMAGE_SCN_GPREL]			Section content can be accessed relative to GP.
00500000h	[IMAGE_SCN_ALIGN_16BYTES]		Default alignment if no others are specified.
01000000h	[IMAGE_SCN_LNK_NRELOC_OVFL]		Section contains extended relocations.
02000000h	[IMAGE_SCN_MEM_DISCARDABLE]		Section can be discarded.
04000000h	[IMAGE_SCN_MEM_NOT_CACHED]		Section is not cachable.
08000000h	[IMAGE_SCN_MEM一NOT一PAGED]		Section is not pageable.
l0000000h	[IMAGE_SCN_MEM一SHARED]			Section is shareable(该块为共享块).
20000000h	[IMAGE_SCN_MEM_EXECUTE]			Section is executable.(该块可执行）
40000000h	[IMAGE_SCN_MEM_READ]			Section is readable.(该块可读）
80000000h	[IMAGE_SCN_MEM_WRITE]			Section is writeable.(该块可写)\n\n\n''')
        print("内存中节的对齐粒度(DWORD)".ljust(25),'SectionAlignment:'.ljust(20),SectionAlignment,'\n',\
            "文件中节的对齐粒度(DWORD)".ljust(25),'FileAlignment:'.ljust(20),FileAlignment,sep='',end='\n\n\n')
        
        section_header={}
        for i in range(NumberOfSection):
            print('节区{}:'.format(i))
            t=Section_Header(PE.read(40).hex().upper())
            section_header[t[0]]=(t[1],t[2],t[3])    #构造数据结构section_header={Section_Name:(PointerToRawData,RVA,VirtualSize),...}
        
        #接下来需要不断跳转stream position,为避免混乱，之后使用PE.read()时默认stream position=0
        PE.seek(0)
        #Import_table=(VirtualAddress,Size)
        #Export_table=(VirtualAddress,Size)
        if SizeOfOptionalHeader!=0xe0:    #64位的暂时不解析导入导出表的内容
            sys.exit()
        Target_Section=Section_deter(Import_table[0],section_header)  #判断导入表输出表在哪个节区
        if Import_table[1]!='00000000' and args.In:
            Import_Table(RVA_to_RAW(Import_table[0],section_header[Target_Section][1],\
                section_header[Target_Section][0]),int(Import_table[1],base=16))
        if Export_table[1]!='00000000' and args.Out:
            Export_Table(RVA_to_RAW(Export_table[0],section_header[Target_Section][1],\
                section_header[Target_Section][0]))

     
        




