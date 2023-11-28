/*
    bfinject - Inject shared libraries into running App Store apps on iOS 11.x < 11.2
    https://github.com/BishopFox/bfinject
    
    Carl Livitt @ Bishop Fox

	Based on code originally by 10n1c: https://github.com/stefanesser/dumpdecrypted/blob/master/dumpdecrypted.c
	Now with the following enhancements:
	- Dump ALL encrypted images in the target application: the app itself, its frameworks, etc.
	- Create a valid .ipa containing the decrypted binaries. Save it in ~/Documents/decrypted-app.ipa
	- The .ipa can be modified and re-signed with a developer cert for redeployment to non-jailbroken devices
	- Auto detection of all the necessary sandbox paths
	- Converted into an Objective-C class for ease of use.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <mach/mach.h>
#include <err.h>
#include <mach-o/ldsyms.h>
#include <libkern/OSCacheControl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>
#import "SSZipArchive/SSZipArchive.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include <mach/vm_map.h>
#include <mach-o/dyld_images.h>
#include <mach/task_info.h>
#include <sys/mman.h>
#include <mach/machine.h>

#include "DumpDecrypted.h"

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
// kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t 
mach_vm_region(vm_map_read_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);


//#define DEBUG(...) NSLog(__VA_ARGS__);
#define DEBUG(...) {}

#define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24) )

unsigned char *readProcessMemory (mach_port_t proc, mach_vm_address_t addr, mach_msg_type_number_t* size) {
    mach_msg_type_number_t  dataCnt = (mach_msg_type_number_t) *size;
    vm_offset_t readMem;
    
    kern_return_t kr = vm_read(proc, addr, *size, &readMem, &dataCnt);
    
    if (kr) {
        //fprintf (stderr, "Unable to read target task's memory @%p - kr 0x%x\n", (void *) addr, kr);
        return NULL;
    }
    
    return ((unsigned char *) readMem);
}

static kern_return_t
readmem(mach_vm_offset_t *buffer, mach_vm_address_t address, mach_vm_size_t size, vm_map_t targetTask, vm_region_basic_info_data_64_t *info)
{
  // get task for pid
  vm_map_t port = targetTask;
  
  kern_return_t kr;
  mach_msg_type_number_t info_cnt = sizeof (vm_region_basic_info_data_64_t);
  mach_port_t object_name;
  mach_vm_size_t size_info;
  mach_vm_address_t address_info = address;
  kr = mach_vm_region(port, &address_info, &size_info, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &info_cnt, &object_name);
  if (kr)
  {
    fprintf(stderr, "[ERROR] mach_vm_region failed with error %d\n", (int)kr);
    return KERN_FAILURE;
  }
  
  /* read memory - vm_read_overwrite because we supply the buffer */
  mach_vm_size_t nread;
  kr = mach_vm_read_overwrite(port, address, size, (mach_vm_address_t)buffer, &nread);
  if (kr)
  {
    fprintf(stderr, "[ERROR] vm_read failed! %d\n", kr);
    return KERN_FAILURE;
  }
  else if (nread != size)
  {
    fprintf(stderr, "[ERROR] vm_read failed! requested size: 0x%llx read: 0x%llx\n", size, nread);
    return KERN_FAILURE;
  }
  return KERN_SUCCESS;
}

int64_t
get_image_size(mach_vm_address_t address, vm_map_t targetTask, uint64_t *vmaddr_slide)
{
  vm_region_basic_info_data_64_t region_info = {0};
  // allocate a buffer to read the header info
  // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
  // but this will work for this purpose so no need for more complexity!
  struct mach_header header = {0};
  if (readmem((mach_vm_offset_t*)&header, address, sizeof(struct mach_header), targetTask, &region_info))
  {
    printf("Can't read header!\n");
    return -1;
  }
  
  if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
  {
		printf("[ERROR] Target is not a mach-o binary!\n");
    return -1;
  }
  
  int64_t imagefilesize = -1;
  /* read the load commands */
  uint8_t *loadcmds = (uint8_t*)malloc(header.sizeofcmds);
  uint16_t mach_header_size = sizeof(struct mach_header);
  if (header.magic == MH_MAGIC_64)
  {
    mach_header_size = sizeof(struct mach_header_64);
  }
  if (readmem((mach_vm_offset_t*)loadcmds, address+mach_header_size, header.sizeofcmds, targetTask, &region_info))
  {
    printf("Can't read load commands\n");
    free(loadcmds);
    return -1;
  }
  
  /* process and retrieve address and size of linkedit */
  uint8_t *loadCmdAddress = 0;
  loadCmdAddress = (uint8_t*)loadcmds;
  struct load_command *loadCommand    = NULL;
  struct segment_command *segCmd      = NULL;
  struct segment_command_64 *segCmd64 = NULL;
  for (uint32_t i = 0; i < header.ncmds; i++)
  {
    loadCommand = (struct load_command*)loadCmdAddress;
    if (loadCommand->cmd == LC_SEGMENT)
    {
      segCmd = (struct segment_command*)loadCmdAddress;
      if (strncmp(segCmd->segname, "__PAGEZERO", 16) != 0)
      {
        if (strncmp(segCmd->segname, "__TEXT", 16) == 0)
        {
          *vmaddr_slide = address - segCmd->vmaddr;
        }
        imagefilesize += segCmd->filesize;
      }
    }
    else if (loadCommand->cmd == LC_SEGMENT_64)
    {
      segCmd64 = (struct segment_command_64*)loadCmdAddress;
      if (strncmp(segCmd64->segname, "__PAGEZERO", 16) != 0)
      {
        if (strncmp(segCmd64->segname, "__TEXT", 16) == 0)
        {
          *vmaddr_slide = address - segCmd64->vmaddr;
        }
        imagefilesize += segCmd64->filesize;
      }
    }
    // advance to next command
    loadCmdAddress += loadCommand->cmdsize;
  }
  free(loadcmds);
  return imagefilesize;
}

int find_off_cryptid(const char *filePath) {
    NSLog(@"[dumpDecrypted] %s filePath: %s", __FUNCTION__, filePath);
    int off_cryptid = 0;
    FILE* file = fopen(filePath, "rb");
    if (!file) return 1;

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = malloc(fileSize);//new char[fileSize];
    size_t readLen = fread(buffer, 1, fileSize, file);

    struct mach_header_64* header = (struct mach_header_64*)buffer;
    if (header->magic != MH_MAGIC_64) {
        printf("[-] error: not a valid macho file\n");
        free(buffer);
        fclose(file);
        return 2;
    }

    struct load_command* lc = (struct load_command*)((mach_vm_address_t)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command *encryption_info = (struct encryption_info_command*) lc;


            NSLog(@"[dumpDecrypted] cryptid: %d\n", encryption_info->cryptid);
            NSLog(@"[dumpDecrypted] Found cryptid at offset: 0x%llx\n", (mach_vm_address_t)lc + offsetof(struct encryption_info_command, cryptid) - (mach_vm_address_t)header);

            off_cryptid = (mach_vm_address_t)lc + offsetof(struct encryption_info_command, cryptid) - (mach_vm_address_t)header;
            break;
        }
        lc = (struct load_command*)((mach_vm_address_t)lc + lc->cmdsize);
    }
    free(buffer);
    fclose(file);

    return off_cryptid;
}

@implementation DumpDecrypted

-(id) initWithPathToBinary:(NSString *)pathToBinary {
	if(!self) {
		self = [super init];
	}

	[self setAppPath:[pathToBinary stringByDeletingLastPathComponent]];
	[self setDocPath:[[[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path]];

	char *lastPartOfAppPath = strdup([[self appPath] UTF8String]);
	lastPartOfAppPath = strrchr(lastPartOfAppPath, '/') + 1;
	DEBUG(@"[dumpdecrypted] init: appDirName: %s", lastPartOfAppPath);
	self->appDirName = strdup(lastPartOfAppPath);

	return self;
}


-(void) makeDirectories:(const char *)encryptedImageFilenameStr {
	char *appPath = (char *)[[self appPath] UTF8String];
	char *docPath = (char *)[[self docPath] UTF8String];
	char *savePtr;
	char *encryptedImagePathStr = savePtr = strdup(encryptedImageFilenameStr);
	self->filename = strdup(strrchr(encryptedImagePathStr, '/') + 1);

	// Normalize the filenames
	if(strstr(encryptedImagePathStr, "/private") == encryptedImagePathStr)
		encryptedImagePathStr += 8;
	if(strstr(appPath, "/private") == appPath)
		appPath += 8;
	
	// Find start of image path, relative to the base of the app sandbox (ie. /var/mobile/.../FooBar.app/THIS_PART_HERE)
	encryptedImagePathStr += strlen(appPath) + 1; // skip over the app path
	char *p = strrchr(encryptedImagePathStr, '/');
	if(p)
		*p = '\0';

	DEBUG(@"[dumpdecrypted] encryptedImagePathStr: %s", encryptedImagePathStr);
	
	NSFileManager *fm = [[NSFileManager alloc] init];
	NSError *err;
	char *lastPartOfAppPath = strdup(appPath); // Must free()
	lastPartOfAppPath = strrchr(lastPartOfAppPath, '/');
	lastPartOfAppPath++;
	NSString *path = [NSString stringWithFormat:@"%s/ipa/Payload/%s", docPath, lastPartOfAppPath];
	self->appDirPath = strdup([path UTF8String]);
	if(p)
		path = [NSString stringWithFormat:@"%@/%s", path, encryptedImagePathStr];

	DEBUG(@"[dumpdecrypted] make_directories making dir: %@", path);
	if(! [fm createDirectoryAtPath:path withIntermediateDirectories:true attributes:nil error:&err]) {
		DEBUG(@"[dumpdecrypted] WARNING: make_directories failed to make directory %@. Error: %@", path, err);
	}

	free(savePtr);

	snprintf(self->decryptedAppPathStr, PATH_MAX, "%s/%s", [path UTF8String], self->filename);

	return;
}

 
-(BOOL) dumpDecryptedImage:(vm_address_t)imageAddress fileName:(const char *)encryptedImageFilenameStr image:(int)imageNum task:(vm_map_t)targetTask{
	// struct load_command *lc;
	struct encryption_info_command *eic;
	struct fat_header *fh;
	struct fat_arch *arch;
	struct mach_header *mh;
	char buffer[1024];
	unsigned int fileoffs = 0, off_cryptid = 0, restsize;
	int i, fd, outfd, r, n;

    struct mach_header header = {0};
    vm_region_basic_info_data_64_t region_info = {0};
    if (readmem((mach_vm_offset_t*)&header, imageAddress, sizeof(struct mach_header), targetTask, &region_info))
    {
        NSLog(@"[dumpDecrypted] Can't read header!");
        exit(1);
    }
    //XXX: change all image_mh -> header NOW
    
    struct load_command *lc = (uint8_t*)malloc(header.sizeofcmds);
	
	/* detect if this is a arm64 binary */
	if (header.magic == MH_MAGIC_64) {
		// lc = (struct load_command *)((unsigned char *)header + sizeof(struct mach_header_64));
        readmem((mach_vm_offset_t*)lc, imageAddress+sizeof(struct mach_header_64), header.sizeofcmds, targetTask, &region_info);
		NSLog(@"[dumpDecrypted] detected 64bit ARM binary in memory.\n");
	} else if(header.magic == MH_MAGIC) { /* we might want to check for other errors here, too */
		// lc = (struct load_command *)((unsigned char *)header + sizeof(struct mach_header));
        readmem((mach_vm_offset_t*)lc, imageAddress+sizeof(struct mach_header), header.sizeofcmds, targetTask, &region_info);
		NSLog(@"[dumpDecrypted] detected 32bit ARM binary in memory.\n");
	} else {
		NSLog(@"[dumpDecrypted] No valid header found!!");
		return false;
	}


    // sleep(1);exit(1);
    const struct mach_header *image_mh = &header;
	
	/* searching all load commands for an LC_ENCRYPTION_INFO load command */
	for (i=0; i<image_mh->ncmds; i++) {
		if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
			eic = (struct encryption_info_command *)lc;
            // struct encryption_info_command *eic = (uint8_t*)malloc(sizeof(struct encryption_info_command););
            // readmem((mach_vm_offset_t*)eic, imageAddress+sizeof(struct mach_header_64), header.sizeofcmds, targetTask, &region_info);
			
			const char *appFilename = strrchr(encryptedImageFilenameStr, '/');
			if(appFilename == NULL) {
				NSLog(@"[dumpDecrypted] There are no / in the filename. This is an error.\n");
				return false;
			}
			appFilename++;

			/* If this load command is present, but data is not crypted then exit */
			if (eic->cryptid == 0) {
				NSLog(@"[dumpDecrypted] CryptID = 0!! ");
				return false;
			}

			// Create a dir structure in ~ just like in /path/to/FooApp.app/Whatever
			[self makeDirectories:encryptedImageFilenameStr];

            //0x1518
            uint32_t aslr_slide = 0;
            int64_t imagesize = get_image_size(imageAddress, targetTask, &aslr_slide);
            NSLog(@"[dumpDecrypted] aslr_slide= 0x%x", aslr_slide);

			off_cryptid=find_off_cryptid(encryptedImageFilenameStr);

			NSLog(@"[dumpDecrypted] offset to cryptid (%d) found in memory @ %p (from %p). off_cryptid = %u (0x%x)\n", eic->cryptid, &eic->cryptid, image_mh, off_cryptid, off_cryptid);
			//NSLog(@"[dumpDecrypted] Found encrypted data at offset %u 0x%08x. image_mh @ %p. cryptedData @ 0x%x. cryptsize = %u (0x%x) bytes.\n", eic->cryptoff, eic->cryptoff, image_mh, (unsigned int)image_mh + eic->cryptoff, eic->cryptsize, eic->cryptsize);
			
			NSLog(@"[dumpDecrypted] Dumping: %s", encryptedImageFilenameStr);
			NSLog(@"[dumpDecrypted]    Into: %s", self->decryptedAppPathStr);
			fd = open(encryptedImageFilenameStr, O_RDONLY);
			if (fd == -1) {
				NSLog(@"[dumpDecrypted] Failed to open %s", encryptedImageFilenameStr);
				return false;
			}
			
			DEBUG(@"[dumpDecrypted] Reading header");
			n = read(fd, (void *)buffer, sizeof(buffer));
			if (n != sizeof(buffer)) {
				NSLog(@"[dumpDecrypted] Warning read only %d of %lu bytes from encrypted file.\n", n, sizeof(buffer));
				return false;
			}

			DEBUG(@"[dumpDecrypted] Detecting header type\n");
			fh = (struct fat_header *)buffer;
			
			/* Is this a FAT file - we assume the right endianess */
			if (fh->magic == FAT_CIGAM) {
				DEBUG(@"[dumpDecrypted] Executable is a FAT image - searching for right architecture\n");
				arch = (struct fat_arch *)&fh[1];
				for (i=0; i<swap32(fh->nfat_arch); i++) {
					if ((image_mh->cputype == swap32(arch->cputype)) && (image_mh->cpusubtype == swap32(arch->cpusubtype))) {
						fileoffs = swap32(arch->offset);
						DEBUG(@"[dumpDecrypted] Correct arch is at offset 0x%x in the file.\n", fileoffs);
						break;
					}
					arch++;
				}
				if (fileoffs == 0) {
					NSLog(@"[dumpDecrypted] Could not find correct arch in FAT image\n");
					return false;
				}
			} else if (fh->magic == MH_MAGIC || fh->magic == MH_MAGIC_64) {
				DEBUG(@"[dumpDecrypted] Executable is a plain MACH-O image, fileoffs = 0\n");
			} else {
				NSLog(@"[dumpDecrypted] Executable is of unknown type, fileoffs = 0\n");
				return false;
			}

			NSLog(@"[dumpDecrypted] Opening %s for writing.\n", decryptedAppPathStr);
			outfd = open(decryptedAppPathStr, O_RDWR|O_CREAT|O_TRUNC, 0644);
			if (outfd == -1) {
				NSLog(@"[dumpDecrypted] Failed opening: ");
				return false;
			}
			
			/* calculate address of beginning of crypted data */
			n = fileoffs + eic->cryptoff;
			
			restsize = lseek(fd, 0, SEEK_END) - n - eic->cryptsize;		
			//NSLog(@"[dumpDecrypted] restsize = %u, n = %u, cryptsize = %u, total = %u", restsize, n, eic->cryptsize, n + eic->cryptsize + restsize);
			lseek(fd, 0, SEEK_SET);
			
			DEBUG(@"[dumpDecrypted] Copying the not encrypted start of the file (%u bytes)\n", n);
			
			/* first copy all the data before the encrypted data */
			char *buf = (char *)malloc((size_t)n);
			r = read(fd, buf, n);
			if(r != n) {
				NSLog(@"[dumpDecrypted] Error reading start of file\n");
				return false;
			}
			r = write(outfd, buf, n);
			if(r != n) {
				NSLog(@"[dumpDecrypted] Error writing start of file\n");
				return  false;
			}
			free(buf);

			/* now write the previously encrypted data */

			NSLog(@"[dumpDecrypted] Dumping the decrypted data into the file (%u bytes)\n", eic->cryptsize);
            buf = (char *)malloc((size_t)eic->cryptsize);
            readmem((mach_vm_offset_t*)buf, imageAddress+eic->cryptoff, eic->cryptsize, targetTask, &region_info);
			// r = write(outfd, (unsigned char *)image_mh + eic->cryptoff, eic->cryptsize);
            r = write(outfd, buf, eic->cryptsize);
			if (r != eic->cryptsize) {
				NSLog(@"[dumpDecrypted] Error writing encrypted part of file\n");
				return false;
			}
            free(buf);
            
			
			/* and finish with the remainder of the file */
			NSLog(@"[dumpDecrypted] Copying the not encrypted remainder of the file (%u bytes)\n", restsize);
			lseek(fd, eic->cryptsize, SEEK_CUR);
			buf = (char *)malloc((size_t)restsize);
			r = read(fd, buf, restsize);
			if (r != restsize) {
				NSLog(@"[dumpDecrypted] Error reading rest of file, got %u bytes\n", r);
				return false;
			}
			r = write(outfd, buf, restsize);
			if (r != restsize) {
				NSLog(@"[dumpDecrypted] Error writing rest of file\n");
				return false;
			}
			free(buf);
            

			if (off_cryptid) {
				uint32_t zero=0;
				NSLog(@"[dumpDecrypted] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset 0x%x into file\n", off_cryptid);
				if (lseek(outfd, off_cryptid, SEEK_SET) == off_cryptid) {
					if(write(outfd, &zero, 4) != 4) {
						NSLog(@"[dumpDecrypted] Error writing cryptid value!!\n");
						// Not a fatal error, just warn
					}
				} else {
					NSLog(@"[dumpDecrypted] Failed to seek to cryptid offset!!");
					// this error is not treated as fatal
				}
			}
	
			close(fd);
			close(outfd);
			sync();
            // exit(1);
			
			return true;
		}
		
		lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);		
        // readmem((mach_vm_offset_t*)lc, lc+lc->cmdsize, header.sizeofcmds, targetTask, &region_info);
	}
	DEBUG(@"[!] This mach-o file is not encrypted. Nothing was decrypted.\n");
	return false;
}


-(void) dumpDecrypted:(pid_t)pid {

    vm_map_t targetTask = 0;
    if (task_for_pid(mach_task_self(), pid, &targetTask))
    {
        NSLog(@"[dumpDecrypted] Can't execute task_for_pid! Do you have the right permissions/entitlements?\n");
        exit(1);
    }

    //numberOfImages
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if(task_info(targetTask, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != KERN_SUCCESS) exit(1);

    mach_msg_type_number_t size = sizeof(struct dyld_all_image_infos);
    uint8_t* data = readProcessMemory(targetTask, dyld_info.all_image_info_addr, &size);
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos *) data;

    mach_msg_type_number_t size2 = sizeof(struct dyld_image_info) * infos->infoArrayCount;
    uint8_t* info_addr = readProcessMemory(targetTask, (mach_vm_address_t) infos->infoArray, &size2);
    struct dyld_image_info* info = (struct dyld_image_info*) info_addr;
        
    uint32_t numberOfImages = infos->infoArrayCount;
    mach_vm_address_t imageAddress = 0;
    const char *appPath = [[self appPath] UTF8String];

    NSLog(@"[dumpDecrypted] There are %d images mapped.", numberOfImages);

    for (int i = 0; i < numberOfImages; i++) {
        DEBUG(@"[dumpDecrypted] image %d", i);
        mach_msg_type_number_t size3 = PATH_MAX;
        uint8_t *fpath_addr = readProcessMemory(targetTask, (mach_vm_address_t) info[i].imageFilePath, &size3);
        
        imageAddress = (struct mach_header *)info[i].imageLoadAddress;
        const char *imageName = fpath_addr;

        if(!imageName || !imageAddress)
			continue;

        DEBUG(@"[dumpDecrypted] Comparing %s to %s", imageName, appPath);

        if(strstr(imageName, appPath) != NULL) {
			NSLog(@"[dumpDecrypted] Dumping image %d: %s", i, imageName);
			[self dumpDecryptedImage:imageAddress fileName:imageName image:i task: targetTask];
		}
    }


    // sleep(1);
    // exit(1);


    /*


	NSLog(@"[dumpDecrypted] There are %d images mapped.", numberOfImages);
	for(int i = 0; i < numberOfImages; i++) {
		DEBUG(@"[dumpDecrypted] image %d", i);
		image_mh = (struct mach_header *)_dyld_get_image_header(i);
		const char *imageName = _dyld_get_image_name(i);

		if(!imageName || !image_mh)
			continue;

		// Attempt to decrypt any image loaded from the app's Bundle directory.
		// This covers the app binary, frameworks, extensions, etc etc
		DEBUG(@"[dumpDecrypted] Comparing %s to %s", imageName, appPath);
        
		if(strstr(imageName, appPath) != NULL) {
			NSLog(@"[dumpDecrypted] Dumping image %d: %s", i, imageName);
			[self dumpDecryptedImage:image_mh fileName:imageName image:i];
		}
	}

    */
}


-(BOOL) fileManager:(NSFileManager *)f shouldProceedAfterError:(BOOL)proceed copyingItemAtPath:(NSString *)path toPath:(NSString *)dest {
	return true;
} 

-(NSString *)IPAPath {
	return [NSString stringWithFormat:@"%@/decrypted-app.ipa", [self docPath]];
}

// Based on code taken from Bishop Fox Firecat
-(int)getSocketForPort:(int)listenPort {
	struct sockaddr_in a;
	int IPAServerSock, clientSock;
	int yes = 1;

	// get a fresh juicy socket
	DEBUG(@"[dumpDecrypted] socket()");
	if((IPAServerSock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		NSLog(@"ERROR: socket()");
		return 0;
	}
	
	// make sure it's quickly reusable
	DEBUG(@"[dumpDecrypted] setsockopt()");
	if(setsockopt(IPAServerSock, SOL_SOCKET, SO_REUSEADDR,	(char *) &yes, sizeof(yes)) < 0) {
		NSLog(@"ERROR: setsockopt()");
		close(IPAServerSock);
		return 0;
	}
	
	// listen on all of the hosts interfaces/addresses (0.0.0.0)
	DEBUG(@"[dumpDecrypted] bind()");
	memset(&a, 0, sizeof(a));
	a.sin_port = htons(listenPort);
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_family = AF_INET;
	if(bind(IPAServerSock, (struct sockaddr *) &a, sizeof(a)) < 0) {
		NSLog(@"ERROR: bind()");
		close(IPAServerSock);
		return 0;
	}
	DEBUG(@"[dumpDecrypted] listen()");
	listen(IPAServerSock, 10);
	
	return IPAServerSock;
}

-(void)IPAServer:(int)listenPort {
	unsigned int i;
	struct sockaddr_in clientAddr;
	int serverSock, clientSock;

	// get a fresh juicy socket
	DEBUG(@"[dumpDecrypted] getSocketForPort()");
	if( ! (serverSock = [self getSocketForPort:listenPort])) {
		NSLog(@"ERROR: socket()");
		return;
	}
	
	i = sizeof(clientAddr);
	
    NSLog(@"[bfdecrypt] Waiting for connection on port %d\n",listenPort);
	if((clientSock = accept(serverSock, (struct sockaddr *)&clientAddr, &i)) == -1) {
		NSLog(@"ERROR: accept(): %s", strerror(errno));
		return;
	}
	
    NSLog(@"[bfdecrypt] Got connection from remote target %s\n", inet_ntoa(clientAddr.sin_addr));
    int fd = open([[self IPAPath] UTF8String], O_RDONLY);
    if(!fd) {
        NSLog(@"[bfdecrypt] Failed to open the IPA file %@!", [self IPAPath]);
		return;
    }

	// I wanted to use sendfile(2), but it's sandboxed by the kernel.
	char buffer[65535];
	int loopCount=0, totalBytes=0;
	DEBUG(@"[bfdecrypt] Entering loop");
	while (1) {
		int bytes_read = read(fd, buffer, sizeof(buffer));
		totalBytes += bytes_read;
		DEBUG(@"[bfdecrypt] %d: Read %d (%d total) bytes from IPA file", loopCount++, bytes_read, totalBytes);
		if(bytes_read == 0) // We're done reading from the file
			break;

		if(bytes_read < 0) {
			NSLog(@"[bfdecrypt] Failed to read() from IPA file");
			break;
		}

		void *p = buffer;
		while(bytes_read > 0) {
			DEBUG(@"[bfdecrypt] Sending %d bytes", bytes_read);
			int bytes_written = send(clientSock, p, bytes_read, 0);
			if (bytes_written <= 0) {
				// handle errors
				NSLog(@"[bfdecrypt] Error sending!");
				break;
			}
			bytes_read -= bytes_written;
			p += bytes_written;
		}
	}

	close(fd);
	shutdown(clientSock, SHUT_RDWR);
	shutdown(serverSock, SHUT_RDWR);
    close(clientSock);
	close(serverSock);
}

-(void) createIPAFile:(pid_t)pid {
	NSString *IPAFile = [self IPAPath];
	NSString *appDir  = [self appPath];
	NSString *appCopyDir = [NSString stringWithFormat:@"%@/ipa/Payload/%s", [self docPath], self->appDirName];
	NSString *zipDir = [NSString stringWithFormat:@"%@/ipa", [self docPath]];
	NSFileManager *fm = [[NSFileManager alloc] init];
	NSError *err;

	[fm removeItemAtPath:IPAFile error:nil];
	[fm removeItemAtPath:appCopyDir error:nil];
	[fm createDirectoryAtPath:appCopyDir withIntermediateDirectories:true attributes:nil error:nil];

	[fm setDelegate:(id<NSFileManagerDelegate>)self];

	NSLog(@"[dumpDecrypted] ======== START FILE COPY - IGNORE ANY SANDBOX WARNINGS ========");
	NSLog(@"[dumpDecrypted] IPAFile: %@", IPAFile);
	NSLog(@"[dumpDecrypted] appDir: %@", appDir);
	NSLog(@"[dumpDecrypted] appCopyDir: %@", appCopyDir);
	NSLog(@"[dumpDecrypted] zipDir: %@", zipDir);
	
	[fm copyItemAtPath:appDir toPath:appCopyDir error:&err];
	NSLog(@"[dumpDecrypted] ======== END OF FILE COPY ========");
    // sleep(1);
    // exit(1);
	// Replace encrypted binaries with decrypted versions
	NSLog(@"[dumpDecrypted] ======== START DECRYPTION PROCESS ========");
	[self dumpDecrypted:pid];
	NSLog(@"[dumpDecrypted] ======== DECRYPTION COMPLETE  ========");

	// ZIP it up
	NSLog(@"[dumpDecrypted] ======== STARTING ZIP ========");
	NSLog(@"[dumpDecrypted] IPA file: %@", IPAFile);
	NSLog(@"[dumpDecrypted] ZIP dir: %@", zipDir);
	unlink([IPAFile UTF8String]);
	@try {
		BOOL success = [SSZipArchive createZipFileAtPath:IPAFile 
										withContentsOfDirectory:zipDir
										keepParentDirectory:NO 
										compressionLevel:1
										password:nil
										AES:NO
										progressHandler:nil
		];
		NSLog(@"[dumpDecrypted] ========  ZIP operation complete: %s ========", (success)?"success":"failed");
	}
	@catch(NSException *e) {
		NSLog(@"[dumpDecrypted] BAAAAAAAARF during ZIP operation!!! , %@", e);
	}
	

	// Clean up. Leave only the .ipa file.
	[fm removeItemAtPath:zipDir error:nil];

	NSLog(@"[dumpDecrypted] ======== Wrote %@ ========", [self IPAPath]);
	return;
}


// Slightly tweaked version of this:
// https://stackoverflow.com/questions/6807788/how-to-get-ip-address-of-iphone-programmatically
- (NSDictionary *)getIPAddresses {
	NSMutableDictionary *addresses = [[NSMutableDictionary alloc] init];
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while(temp_addr != NULL) {
            if(temp_addr->ifa_addr->sa_family == AF_INET) {
				DEBUG(@"Got IF %s  // ip: %s", temp_addr->ifa_name, inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr));
                // Check if interface is en0 which is the wifi connection on the iPhone
				[addresses 	setValue:[NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)]
							forKey:[NSString stringWithUTF8String:temp_addr->ifa_name]];
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    // Free memory
    freeifaddrs(interfaces);
    return addresses;
} 

@end
