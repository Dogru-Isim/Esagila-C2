#include <windows.h>
#include <windef.h>
#include <stdio.h>

CHAR* hello = "hello";
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow)
{
    // Get the base address (IMAGE_DOS_HEADER)
    extern IMAGE_DOS_HEADER __ImageBase;
    printf("__ImageBase: %p\n", &__ImageBase);

    // Get the offset to the IMAGE_NT_HEADERS struct
    LONG ntHeaderOffset  = __ImageBase.e_lfanew;
    printf("ntHeaderOffset: %lu\n", ntHeaderOffset);

    // Get the IMAGE_NT_HEADERS struct
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)(&__ImageBase) + ntHeaderOffset);
    printf("pNtHeader: %p\n", pNtHeader);

    // Get the first section
    PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNtHeader);
    printf("pFirstSection: %p\n", pFirstSection);

    // Get the IMAGE_FILE_HEADER struct
    PIMAGE_FILE_HEADER pImageFileHeader = &pNtHeader->FileHeader;
    printf("pImageFileHeader: %p\n", pImageFileHeader);

    // Get the number of sections
    WORD wNumberOfSections = pImageFileHeader->NumberOfSections;
    printf("wNumberOfSections: %d\n", wNumberOfSections);

    // Get the size of IMAGE_OPTIONAL_HEADER64
    WORD wSizeOfOptionalHeader = pImageFileHeader->SizeOfOptionalHeader;
    printf("wSizeOfOptionalHeader: %d\n", wSizeOfOptionalHeader);

    // Get the IMAGE_OPTIONAL_HEADER64 struct
    PIMAGE_OPTIONAL_HEADER64 pImageOptionalHeader = &pNtHeader->OptionalHeader;
    printf("pImageOptionalHeader: %p\n", pImageOptionalHeader);

    // Get the first section
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pImageOptionalHeader + wSizeOfOptionalHeader);
    PVOID pDataSection;

    // find the .data section
    for (int i = 0; i < wNumberOfSections; i++)
    {
        printf("pSectionHeader: %p\n", pSectionHeader);

        CHAR* pSectionName = (CHAR*)pSectionHeader->Name;
        printf("Section name: %.8s\n", pSectionName);

        // check if section name is .data
        if (strcmp(pSectionName, ".data") == 0)
        {
            //pDataSection = (PVOID)((ULONG_PTR)(&__ImageBase) + pSectionHeader->VirtualAddress);
            pDataSection = (PVOID)((ULONG_PTR)(&__ImageBase) + pSectionHeader->PointerToRawData);
            printf("Found .data: %p\n", pDataSection);
            /*
            for (int j = 0; i < pSectionHeader->SizeOfRawData)
            {
            */
            printf(".data section:\n %s\n", (CHAR*)pDataSection);
            break;
        }

        pSectionHeader = (PIMAGE_SECTION_HEADER)((LONG_PTR)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER*(i+1));
    }

    return 0;
}

/*
https://stackoverflow.com/questions/23498583/pe-section-data

I have an Portable Executable ( .exe ) file and I want to retrieve its sections. I did like this:

IMAGE_DOS_HEADER* pDOSHeader = (IMAGE_DOS_HEADER*) buffer; // DOS Header
IMAGE_NT_HEADERS* pNTHeaders = (IMAGE_NT_HEADERS*) ((BYTE *) pDOSHeader + pDOSHeader->e_lfanew); // PE Header   

Everything good until now. I found this:

    The section table: This follows immediately after the PE header. It is an array of IMAGE_SECTION_HEADER structures, each containing the information about one section in the PE file such as its attribute and virtual offset. Remember the number of sections is the second member of FileHeader (6 bytes from the start of the PE header). If there are 8 sections in the PE file, there will be 8 duplicates of this structure in the table. Each header structure is 40 bytes apiece and there is no "padding" between them.

Now, when I do like this:

IMAGE_SECTION_HEADER* pSection = (IMAGE_SECTION_HEADER*) 
(pNTHeaders->FileHeader.PointerToSymbolTable);

or:

IMAGE_SECTION_HEADER* pSection = (IMAGE_SECTION_HEADER*) ((BYTE *) pNTHeaders + sizeof(IMAGE_NT_HEADERS));

pSection's address is NULL ( 0 ).

I have to mention that buffer variable is where I read the PE's data.

*/
