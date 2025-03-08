#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <windows.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#pragma pack(push,1)
struct BootSector {
    uint8_t     jump[3];
    char        name[8];
    uint16_t    bytesPerSector;
    uint8_t     sectorsPerCluster;
    uint16_t    reservedSectors;
    uint8_t     unused0[3];
    uint16_t    unused1;
    uint8_t     media;
    uint16_t    unused2;
    uint16_t    sectorsPerTrack;
    uint16_t    headsPerCylinder;
    uint32_t    hiddenSectors;
    uint32_t    unused3;
    uint32_t    unused4;
    uint64_t    totalSectors;
    uint64_t    mftStart;
    uint64_t    mftMirrorStart;
    uint32_t    clustersPerFileRecord;
    uint32_t    clustersPerIndexBlock;
    uint64_t    serialNumber;
    uint32_t    checksum;
    uint8_t     bootloader[426];
    uint16_t    bootSignature;
};

struct FileRecordHeader {
    uint32_t    magic;
    uint16_t    updateSequenceOffset;
    uint16_t    updateSequenceSize;
    uint64_t    logSequence;
    uint16_t    sequenceNumber;
    uint16_t    hardLinkCount;
    uint16_t    firstAttributeOffset;
    uint16_t    inUse : 1;
    uint16_t    isDirectory : 1;
    uint32_t    usedSize;
    uint32_t    allocatedSize;
    uint64_t    fileReference;
    uint16_t    nextAttributeID;
    uint16_t    unused;
    uint32_t    recordNumber;
};

struct AttributeHeader {
    uint32_t    attributeType;
    uint32_t    length;
    uint8_t     nonResident;
    uint8_t     nameLength;
    uint16_t    nameOffset;
    uint16_t    flags;
    uint16_t    attributeID;
};

struct ResidentAttributeHeader : AttributeHeader {
    uint32_t    attributeLength;
    uint16_t    attributeOffset;
    uint8_t     indexed;
    uint8_t     unused;
};

struct FileNameAttributeHeader : ResidentAttributeHeader {
    uint64_t    parentRecordNumber : 48;
    uint64_t    sequenceNumber : 16;
    uint64_t    creationTime;
    uint64_t    modificationTime;
    uint64_t    metadataModificationTime;
    uint64_t    readTime;
    uint64_t    allocatedSize;
    uint64_t    realSize;
    uint32_t    flags;
    uint32_t    repase;
    uint8_t     fileNameLength;
    uint8_t     namespaceType;
    wchar_t     fileName[1];
};

struct NonResidentAttributeHeader : AttributeHeader {
    uint64_t    firstCluster;
    uint64_t    lastCluster;
    uint16_t    dataRunsOffset;
    uint16_t    compressionUnit;
    uint32_t    unused;
    uint64_t    attributeAllocated;
    uint64_t    attributeSize;
    uint64_t    streamDataSize;
};

struct RunHeader {
    uint8_t     lengthFieldBytes : 4;
    uint8_t     offsetFieldBytes : 4;
};
#pragma pack(pop)

struct File {
    uint64_t    parent;
    char* name;
};


DWORD bytesAccessed;
HANDLE drive;

BootSector bootSector;

#define MFT_FILE_SIZE (1024)
uint8_t mftFile[MFT_FILE_SIZE];

#define MFT_FILES_PER_BUFFER (65536)
uint8_t mftBuffer[MFT_FILES_PER_BUFFER * MFT_FILE_SIZE];

char* DuplicateName(wchar_t* name, size_t nameLength) {
    static char* allocationBlock = nullptr;
    static size_t bytesRemaining = 0;

    size_t bytesNeeded = WideCharToMultiByte(CP_UTF8, 0, name, nameLength, NULL, 0, NULL, NULL) + 1;

    if (bytesRemaining < bytesNeeded) {
        allocationBlock = (char*)malloc((bytesRemaining = 16 * 1024 * 1024));
    }

    char* buffer = allocationBlock;
    buffer[bytesNeeded - 1] = 0;
    WideCharToMultiByte(CP_UTF8, 0, name, nameLength, allocationBlock, bytesNeeded, NULL, NULL);

    bytesRemaining -= bytesNeeded;
    allocationBlock += bytesNeeded;

    return buffer;
}

void Read(void* buffer, uint64_t from, uint64_t count) {
    LONG high = from >> 32;
    SetFilePointer(drive, from & 0xFFFFFFFF, &high, FILE_BEGIN);
    ReadFile(drive, buffer, count, &bytesAccessed, NULL);
    assert(bytesAccessed == count);
}

int main(int argc, char** argv) {
    drive = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    

    Read(&bootSector, 0, 512);

    uint64_t bytesPerCluster = bootSector.bytesPerSector * bootSector.sectorsPerCluster;
    //printf("bytes per cluster: %llu\n", bytesPerCluster);

	Read(&mftFile, bootSector.mftStart* bytesPerCluster, MFT_FILE_SIZE);

	FileRecordHeader* fileRecord = (FileRecordHeader*)mftFile;
	AttributeHeader* attribute = (AttributeHeader*)(mftFile + fileRecord->firstAttributeOffset);
	NonResidentAttributeHeader* dataAttribute = nullptr;
	uint64_t approximateRecordCount = 0;
	assert(fileRecord->magic == 0x454C4946);

	while (true) {
		if (attribute->attributeType == 0x80) {
			dataAttribute = (NonResidentAttributeHeader*)attribute;
		}
		else if (attribute->attributeType == 0xB0) {
			approximateRecordCount = ((NonResidentAttributeHeader*)attribute)->attributeSize * 8;
		}
		else if (attribute->attributeType == 0xFFFFFFFF) {
			break;
		}

		attribute = (AttributeHeader*)((uint8_t*)attribute + attribute->length);
	}

	assert(dataAttribute);
    //printf("Magic offset value: %llu\n", dataAttribute->dataRunsOffset);
	RunHeader* dataRun = (RunHeader*)((uint8_t*)dataAttribute + dataAttribute->dataRunsOffset);
	uint64_t clusterNumber = 0, recordsProcessed = 0;

	while (((uint8_t*)dataRun - (uint8_t*)dataAttribute) < dataAttribute->length && dataRun->lengthFieldBytes) {
		uint64_t length = 0, offset = 0;

		for (int i = 0; i < dataRun->lengthFieldBytes; i++) {
			length |= (uint64_t)(((uint8_t*)dataRun)[1 + i]) << (i * 8);
		}

		for (int i = 0; i < dataRun->offsetFieldBytes; i++) {
			offset |= (uint64_t)(((uint8_t*)dataRun)[1 + dataRun->lengthFieldBytes + i]) << (i * 8);
		}

		if (offset & ((uint64_t)1 << (dataRun->offsetFieldBytes * 8 - 1))) {
			for (int i = dataRun->offsetFieldBytes; i < 8; i++) {
				offset |= (uint64_t)0xFF << (i * 8);
			}
		}

		clusterNumber += offset;
		dataRun = (RunHeader*)((uint8_t*)dataRun + 1 + dataRun->lengthFieldBytes + dataRun->offsetFieldBytes);

		uint64_t filesRemaining = length * bytesPerCluster / MFT_FILE_SIZE;
		uint64_t positionInBlock = 0;

		while (filesRemaining) {
			//fprintf(stderr, "%d%% ", (int)(recordsProcessed * 100 / approximateRecordCount));

			uint64_t filesToLoad = MFT_FILES_PER_BUFFER;
			if (filesRemaining < MFT_FILES_PER_BUFFER) filesToLoad = filesRemaining;
            //printf("Reading: %llu bytes (%llu to %llu)\n", filesToLoad * MFT_FILE_SIZE, (uint8_t*)(clusterNumber*bytesPerCluster+positionInBlock), (uint8_t*)(clusterNumber*bytesPerCluster+positionInBlock + (filesToLoad*MFT_FILE_SIZE)));
			Read(&mftBuffer, clusterNumber * bytesPerCluster + positionInBlock, filesToLoad * MFT_FILE_SIZE);
			positionInBlock += filesToLoad * MFT_FILE_SIZE;
			filesRemaining -= filesToLoad;

			for (int i = 0; i < filesToLoad; i++) {
				// Even on an SSD, processing the file records takes only a fraction of the time to read the data,
				// so there's not much point in multithreading this.

				FileRecordHeader* fileRecord = (FileRecordHeader*)(mftBuffer + MFT_FILE_SIZE * i); // buffer read from file + offset
				recordsProcessed++;

				if (!fileRecord->inUse) continue;

				AttributeHeader* attribute = (AttributeHeader*)((uint8_t*)fileRecord + fileRecord->firstAttributeOffset); // converts pointer back to offset in buffer and changes it?
				FileNameAttributeHeader* fileNameAttribute = (FileNameAttributeHeader*)attribute;
				assert(fileRecord->magic == 0x454C4946);

				NonResidentAttributeHeader* file_dataAttribute = nullptr;

				while ((uint8_t*)attribute - (uint8_t*)fileRecord < MFT_FILE_SIZE) {
					if (attribute->attributeType == 0x30) {
						fileNameAttribute = (FileNameAttributeHeader*)attribute;

						if (fileNameAttribute->namespaceType != 2 && !fileNameAttribute->nonResident) {
                            /*
							File file = {};
							file.parent = fileNameAttribute->parentRecordNumber;
							char* name = DuplicateName(fileNameAttribute->fileName, fileNameAttribute->fileNameLength);
							printf("filename: %s\n", name); //check it is the pagefile.
                            */
						}

					}

					if (attribute->attributeType == 0x80) {
						file_dataAttribute = (NonResidentAttributeHeader*)attribute;
					}

					else if (attribute->attributeType == 0xFFFFFFFF) {
						break;
					}

					attribute = (AttributeHeader*)((uint8_t*)attribute + attribute->length);
				}
                char* name = DuplicateName(fileNameAttribute->fileName, fileNameAttribute->fileNameLength);
				if (strcmp(name, "pagefile.sys") == 0){
                    //printf("filenameattribute: %llu\n", (uint8_t*)fileNameAttribute);
					//printf("filename: %ws\n", fileNameAttribute->fileName);
                    //printf("Rundataoffset: %llu\n", file_dataAttribute->dataRunsOffset);
                    //printf("file length: %llu\n", file_dataAttribute->streamDataSize);
                    //printf("File_dataAttribute: %llu\n", (uint8_t*)file_dataAttribute);
                    //printf("file_dataAttribute->type: 0x%x\n", file_dataAttribute->attributeType);
                    if (file_dataAttribute->nonResident == 0) {
                        printf("[Error] File is resident, no Data Runs available!\n");
                        return 0;
                    }
                    else {
                        printf("File is a non resident file\n");
                    }
					RunHeader* file_dataRun = (RunHeader*)((uint8_t*)file_dataAttribute + file_dataAttribute->dataRunsOffset);
                    printf("file_dataRun->lengthFiledBytes: %llu\n", file_dataRun->lengthFieldBytes);
                    printf("file_dataRun->offsetfieldbytes: %llu\n", file_dataRun->offsetFieldBytes);

                    uint64_t file_clusterNumber = 0;
                    LPVOID outputbuffer = NULL;

                    HANDLE hOutfile = CreateFileA("dumpedfile.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    outputbuffer = VirtualAlloc(NULL, bytesPerCluster, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                    HANDLE hDisk_file_read = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

                    if (outputbuffer == NULL) {
                        printf("[!] Could not allocate buffer, you have fucked up very badly\n");
                        return 0;
                    }


                    while (((uint8_t*)file_dataRun - (uint8_t*)file_dataAttribute) < file_dataAttribute->length && file_dataRun->lengthFieldBytes) {
                        uint64_t length = 0,
                            offset = 0;
                        for (int i = 0; i < file_dataRun->lengthFieldBytes; i++) {
                            length |= (uint64_t)(((uint8_t*)file_dataRun)[1 + i]) << (i * 8);
                        }
                        for (int i = 0; i < file_dataRun->offsetFieldBytes; i++) {
                            offset |= (uint64_t)(((uint8_t*)file_dataRun)[1 + file_dataRun->lengthFieldBytes + i]) << (i * 8);
                        }
                        if (offset & ((uint64_t)1 << (file_dataRun->offsetFieldBytes * 8 - 1))) {
                            for (int i = file_dataRun->offsetFieldBytes; i < 8; i++) {
                                offset |= (uint64_t)0xFF << (i * 8);
                            }
                        }

                        file_clusterNumber += offset;
                        file_dataRun = (RunHeader*)((uint8_t*)file_dataRun + 1 + file_dataRun->lengthFieldBytes + file_dataRun->offsetFieldBytes);

                        printf("%llu sectors starting at cluster id: %llu\n", length, file_clusterNumber);
                        printf("Writing %llu sectors to disk...", length);
                        for (int i = 0; i < (length - 1); i++) {
                            uint64_t byteoffset = (file_clusterNumber + i) * bytesPerCluster;
                            DWORD bytesRead = 0;
                            DWORD bytesWritten = 0;
							LARGE_INTEGER li = { 0 };
                            li.QuadPart = byteoffset;

                            if (!SetFilePointerEx(hDisk_file_read, li, NULL, FILE_BEGIN)) {
                                printf("[!] You cant read this sector on the disk, file IO fuckery?\n");
                            }
                            if (!ReadFile(hDisk_file_read, outputbuffer, bytesPerCluster, &bytesRead, NULL)){
                                printf("btyesread %llu\nbtyespercluster %llu\n", bytesRead, bytesPerCluster);
                                printf("Error reading disk at offset %llu: %lu\n", byteoffset, GetLastError());
                            }

                            if (!WriteFile(hOutfile, outputbuffer, bytesRead, &bytesWritten, NULL)) {
                                printf("byteswritten %llu\nbytesread %llu\n", bytesWritten, bytesRead);
                                printf("Error writing to output file: %lu\n", GetLastError());
                            }

                        }
                        // read final sector
                        DWORD to_read = file_dataAttribute->streamDataSize % bytesPerCluster;

                        if (to_read == 0) {
                            to_read = bytesPerCluster;
                        }
                        LARGE_INTEGER li = { 0 };
                        uint64_t byteoffset = (file_clusterNumber + length-1) * bytesPerCluster;
                        li.QuadPart = byteoffset;
                        DWORD bytesRead = 0;
                        DWORD bytesWritten = 0;

                        if (!SetFilePointerEx(hDisk_file_read, li, NULL, FILE_BEGIN)) {
                            printf("[!] You cant read this sector on the disk, file IO fuckery?\n");
                        }
                        printf("to_read = %llu\n", to_read);
                        if (!ReadFile(hDisk_file_read, outputbuffer, bytesPerCluster, &bytesRead, NULL)) {
                            printf("btyesread %llu\nbtyespercluster %llu\n", bytesRead, bytesPerCluster);
                            printf("[!] ");
                            printf("Error reading disk at offset %llu: %lu\n", byteoffset, GetLastError());
                        }

                        if (!WriteFile(hOutfile, outputbuffer, to_read, &bytesWritten, NULL)) {
                            printf("byteswritten %llu\nbytesread %llu\n", bytesWritten, bytesRead);
                            printf("Error writing to output file: %lu\n", GetLastError());
                        }
                        
                        CloseHandle(hDisk_file_read);
                        CloseHandle(hOutfile);

                    }
                    return 0;

				}
			}
		}
	}
    printf("[+] Done!\n");
    return 0;
}
