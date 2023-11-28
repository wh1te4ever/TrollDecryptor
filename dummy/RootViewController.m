#import "RootViewController.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <fcntl.h>
#include <mach/task_info.h>



@interface RootViewController ()
@property (nonatomic, strong) NSMutableArray * objects;
@end

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t 
mach_vm_region(vm_map_read_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);


kern_return_t
dump_binary(mach_vm_address_t address, pid_t pid, uint8_t *buffer, uint64_t aslr_slide, char* segment_name, int *segment_size);

int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
struct proc_bsdinfo {
	uint32_t		pbi_flags;		/* 64bit; emulated etc */
	uint32_t		pbi_status;
	uint32_t		pbi_xstatus;
	uint32_t		pbi_pid;
	uint32_t		pbi_ppid;
	uid_t			pbi_uid;
	gid_t			pbi_gid;
	uid_t			pbi_ruid;
	gid_t			pbi_rgid;
	uid_t			pbi_svuid;
	gid_t			pbi_svgid;
	uint32_t		rfu_1;			/* reserved */
	char			pbi_comm[MAXCOMLEN];
	char			pbi_name[2*MAXCOMLEN];	/* empty if no name is registered */
	uint32_t		pbi_nfiles;
	uint32_t		pbi_pgid;
	uint32_t		pbi_pjobc;
	uint32_t		e_tdev;			/* controlling tty dev */
	uint32_t		e_tpgid;		/* tty process group id */
	int32_t			pbi_nice;
	uint64_t		pbi_start_tvsec;
	uint64_t		pbi_start_tvusec;
};
int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);

#define PROC_ALL_PIDS		1
#define PROC_PIDTBSDINFO		3
#define PROC_PIDTBSDINFO_SIZE		(sizeof(struct proc_bsdinfo))



int find_pid_by_name(const char *name)
{
    pid_t pids[2048];
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    int n_proc = bytes / sizeof(pids[0]);
    for (int i = 0; i < n_proc; i++) {
        struct proc_bsdinfo proc;
        int st = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0,
                             &proc, PROC_PIDTBSDINFO_SIZE);
        if (st == PROC_PIDTBSDINFO_SIZE) {
            if (strcmp(name, proc.pbi_name) == 0) {
                /* Process PID */
                printf("%d [%s] [%s]\n", pids[i], proc.pbi_comm, proc.pbi_name);  
				return pids[i];              
            }
        }       
    }
	return -1;
}

kern_return_t
find_main_binary(pid_t pid, mach_vm_address_t *main_address)
{
  vm_map_t targetTask = 0;
  kern_return_t kr = 0;
  if (task_for_pid(mach_task_self(), pid, &targetTask))
  {
    printf("[-] Can't execute task_for_pid! Do you have the right permissions/entitlements?\n");
    return KERN_FAILURE;
  }
  
  vm_address_t iter = 0;
  while (1)
  {
    struct mach_header mh = {0};
    vm_address_t addr = iter;
    vm_size_t lsize = 0;
    uint32_t depth;
    mach_vm_size_t bytes_read = 0;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    if (vm_region_recurse_64(targetTask, &addr, &lsize, &depth, (vm_region_info_t)&info, &count))
    {
      break;
    }
    kr = mach_vm_read_overwrite(targetTask, (mach_vm_address_t)addr, (mach_vm_size_t)sizeof(struct mach_header), (mach_vm_address_t)&mh, &bytes_read);
    if (kr == KERN_SUCCESS && bytes_read == sizeof(struct mach_header))
    {
      /* only one image with MH_EXECUTE filetype */
      if ( (mh.magic == MH_MAGIC || mh.magic == MH_MAGIC_64) && mh.filetype == MH_EXECUTE)
      {
        *main_address = addr;
        break;
      }
    }
    iter = addr + lsize;
  }
  return KERN_SUCCESS;
}

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

void HexDump(uint64_t addr, size_t size) {
    void *data = malloc(size);
    data = addr;
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        if ((i % 16) == 0)
        {
            NSLog(@"[IPADecLog] [0x%016llx+0x%03zx] ", addr, i);
//            printf("[0x%016llx] ", i + addr);
        }
        
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            NSLog(@"[IPADecLog] ");
            if ((i+1) % 16 == 0) {
                printf("[IPADecLog]|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    NSLog(@"[IPADecLog] ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    NSLog(@"[IPADecLog]   ");
                }
                NSLog(@"[IPADecLog] |  %s \n", ascii);
            }
        }
    }
    free(data);
}

static kern_return_t
readmem(mach_vm_offset_t *buffer, mach_vm_address_t address, mach_vm_size_t size, pid_t pid, vm_region_basic_info_data_64_t *info)
{
  // get task for pid
  vm_map_t port;
  
  kern_return_t kr;
  if (task_for_pid(mach_task_self(), pid, &port))
  {
    fprintf(stderr, "[ERROR] Can't execute task_for_pid! Do you have the right permissions/entitlements?\n");
    return KERN_FAILURE;
  }
  
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
get_image_size(mach_vm_address_t address, pid_t pid, uint64_t *vmaddr_slide)
{
  vm_region_basic_info_data_64_t region_info = {0};
  // allocate a buffer to read the header info
  // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
  // but this will work for this purpose so no need for more complexity!
  struct mach_header header = {0};
  if (readmem((mach_vm_offset_t*)&header, address, sizeof(struct mach_header), pid, &region_info))
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
  if (readmem((mach_vm_offset_t*)loadcmds, address+mach_header_size, header.sizeofcmds, pid, &region_info))
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

kern_return_t
find_sub_library(pid_t pid, mach_vm_address_t *address)
{
  vm_map_t targetTask = 0;
  kern_return_t kr = 0;
  if (task_for_pid(mach_task_self(), pid, &targetTask))
  {
    printf("[-] Can't execute task_for_pid! Do you have the right permissions/entitlements?\n");
    return KERN_FAILURE;
  }

struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(targetTask, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS)
    {
        mach_msg_type_number_t size = sizeof(struct dyld_all_image_infos);
        
        uint8_t* data = readProcessMemory(targetTask, dyld_info.all_image_info_addr, &size);
        struct dyld_all_image_infos* infos = (struct dyld_all_image_infos *) data;
        
        mach_msg_type_number_t size2 = sizeof(struct dyld_image_info) * infos->infoArrayCount;
        uint8_t* info_addr = readProcessMemory(targetTask, (mach_vm_address_t) infos->infoArray, &size2);
        struct dyld_image_info* info = (struct dyld_image_info*) info_addr;
        
		NSLog(@"[IPADecLog] %s infos->infoArrayCount: %d", __FUNCTION__, infos->infoArrayCount);
		int dylib_count = 0;
        for (int i=0; i < infos->infoArrayCount; i++) {
            mach_msg_type_number_t size3 = PATH_MAX;
            uint8_t* fpath_addr = readProcessMemory(targetTask, (mach_vm_address_t) info[i].imageFilePath, &size3);
            if (fpath_addr && strstr(fpath_addr, "KakaoTalk.app") != NULL) {
				dylib_count++;
				uint64_t aslr_slide = 0;
				int64_t imagesize = get_image_size(info[i].imageLoadAddress, pid, &aslr_slide);
                NSLog(@"[IPADecLog] path: %s %d, address: %p, imagesize: 0x%llx, aslr_slide: 0x%llx\n",fpath_addr , size3, info[i].imageLoadAddress, imagesize, aslr_slide);
				
				uint8_t *readbuffer = (uint8_t*)malloc(imagesize);
				NSLog(@"[IPADecLog] [i] buffer allocated: %p, size: 0x%llx\n", readbuffer, imagesize);

				int segment_size = 0;
				if (dump_binary(info[i].imageLoadAddress, pid, readbuffer, aslr_slide, "__LINKEDIT", &segment_size)) {

				}
			}
		}
		NSLog(@"[IPADecLog] %s dylib_count: %d", __FUNCTION__, dylib_count);
	}
  
	return KERN_SUCCESS;
}


kern_return_t
dump_binary(mach_vm_address_t address, pid_t pid, uint8_t *buffer, uint64_t aslr_slide, char* segment_name, int *segment_size)
{
  vm_region_basic_info_data_64_t region_info = {0};
  // allocate a buffer to read the header info
  // NOTE: this is not exactly correct since the 64bit version has an extra 4 bytes
  // but this will work for this purpose so no need for more complexity!
  struct mach_header header = {0};
  if (readmem((mach_vm_offset_t*)&header, address, sizeof(struct mach_header), pid, &region_info))
  {
    printf("Can't read header!\n");
    return KERN_FAILURE;
  }
  
  if (header.magic != MH_MAGIC && header.magic != MH_MAGIC_64)
  {
    printf("[ERROR] Target is not a mach-o binary!\n");
    return KERN_FAILURE;
  }
  
  // read the header info to find the LINKEDIT
  uint8_t *loadcmds = (uint8_t*)malloc(header.sizeofcmds);
  
  uint16_t mach_header_size = sizeof(struct mach_header);
  if (header.magic == MH_MAGIC_64)
  {
    mach_header_size = sizeof(struct mach_header_64);
  }
  // retrieve the load commands
  if (readmem((mach_vm_offset_t*)loadcmds, address+mach_header_size, header.sizeofcmds, pid, &region_info))
  {
    printf("Can't read load commands\n");
    free(loadcmds);
    loadcmds = NULL;
    return KERN_FAILURE;
  }
  
  	// process and retrieve address and size of linkedit
  	uint8_t *loadCmdAddress = 0;
  	loadCmdAddress = (uint8_t*)loadcmds;
  	struct load_command *loadCommand    = NULL;
  	struct segment_command *segCmd      = NULL;
  	struct segment_command_64 *segCmd64 = NULL;
	struct encryption_info_command *eic;
	unsigned int fileoffs = 0, off_cryptid = 0, restsize;
  	for (uint32_t i = 0; i < header.ncmds; i++)
  	{
    	loadCommand = (struct load_command*)loadCmdAddress;
		if(loadCommand->cmd == LC_LOAD_DYLIB) {
			// NSLog(@"[IPADecLog] Found loadCommand->cmd ==  LC_LOAD_DYLIB");
			struct dylib_command *dc = (struct dylib_command *)loadCommand;
            struct dylib dy = dc->dylib;
            const char *detectedDyld = (char*)dc + dy.name.offset;
			if(strstr(detectedDyld, "@rpath") != NULL) {
				NSLog(@"[IPADecLog] Loaded dyld: %s", detectedDyld);
				// struct mach_header *lib_mh = (struct mach_header *)(dc + dylib_cmd->dylib.name.offset);
			}
		}

		else if(loadCommand->cmd == LC_ENCRYPTION_INFO || loadCommand->cmd == LC_ENCRYPTION_INFO_64) {
			NSLog(@"[IPADecLog] Found loadCommand->cmd ==  LC_ENCRYPTION_INFO/64");
			eic = (struct encryption_info_command *)loadCommand;
			NSLog(@"[IPADecLog] eic->cryptid: %d", eic->cryptid);
			NSLog(@"[IPADecLog] eic->cryptsize: %d", eic->cryptsize);
		}
    	else if(loadCommand->cmd == LC_SEGMENT)
    	{
      		segCmd = (struct segment_command*)loadCmdAddress;
			// printf("LC_SEGMENT segCmd->segname: %s\n", segCmd->segname);
		}
		else if (loadCommand->cmd == LC_SEGMENT_64)
    	{
      		segCmd64 = (struct segment_command_64*)loadCmdAddress;
			NSLog(@"[IPADecLog] LC_SEGMENT_64 segCmd->segname: %s\n", segCmd64->segname);
			if(strcmp(segCmd64->segname, segment_name) == 0) {
				// buffer += segCmd64->filesize;
				NSLog(@"[IPADecLog] [+] Found %s at 0x%llx with size 0x%llx\n", segCmd64->segname, segCmd64->vmaddr+aslr_slide, segCmd64->filesize);
				readmem((mach_vm_offset_t*)buffer, segCmd64->vmaddr+aslr_slide, segCmd64->filesize, pid, &region_info);
				*segment_size = segCmd64->filesize;
			}
    	}
		loadCmdAddress += loadCommand->cmdsize;
  	}
	free(loadcmds);
  	loadcmds = NULL;
  	return KERN_SUCCESS;
}


@implementation RootViewController

- (void)loadView {
	[super loadView];

	_button = [UIButton buttonWithType:UIButtonTypeSystem];
  _button.frame = CGRectMake(UIScreen.mainScreen.bounds.size.width / 2 - 30,
                             UIScreen.mainScreen.bounds.size.height / 2 - 25, 60, 50);
  [_button setTitle:@"Test" forState:UIControlStateNormal];
  [_button addTarget:self
                action:@selector(buttonPressed:)
      forControlEvents:UIControlEventTouchUpInside];
  [self.view addSubview:_button];

	// _objects = [NSMutableArray array];

	// self.title = @"Root View Controller";
	// self.navigationItem.leftBarButtonItem = self.editButtonItem;
	// self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd target:self action:@selector(addButtonTapped:)];
}

- (void)buttonPressed:(UIButton *)sender {
  NSLog(@"[IPADecLog] Hello, World!");
  
  int katalk_pid = find_pid_by_name("KakaoTalk");
  NSLog(@"[IPADecLog] katalk_pid: %d", katalk_pid);

  mach_vm_address_t mainAddress = 0;
  find_main_binary(katalk_pid, &mainAddress);
  NSLog(@"[IPADecLog] katalk mainAddress: 0x%llx", mainAddress);

  uint64_t aslr_slide = 0;
    uint64_t imagesize = 0;
    imagesize = get_image_size(mainAddress, katalk_pid, &aslr_slide);
	NSLog(@"[IPADecLog] [+] image size: 0x%llx, aslr_slide: 0x%llx\n", imagesize, aslr_slide);

	uint8_t *readbuffer = (uint8_t*)malloc(imagesize);
	NSLog(@"[IPADecLog] [i] buffer allocated: %p, size: 0x%llx\n", readbuffer, imagesize);

	int segment_size = 0;
	if (dump_binary(mainAddress, katalk_pid, readbuffer, aslr_slide, "__LINKEDIT", &segment_size))
    {
      NSLog(@"[IPADecLog] Failed to dump memory of __LINKEDIT segment!\n");
      free(readbuffer);
    }

	find_sub_library(katalk_pid, NULL);
}

// - (void)addButtonTapped:(id)sender {
// 	[_objects insertObject:[NSDate date] atIndex:0];
// 	[self.tableView insertRowsAtIndexPaths:@[ [NSIndexPath indexPathForRow:0 inSection:0] ] withRowAnimation:UITableViewRowAnimationAutomatic];
// }

// #pragma mark - Table View Data Source

// - (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
// 	return 1;
// }

// - (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
// 	return _objects.count;
// }

// - (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
// 	static NSString *CellIdentifier = @"Cell";
// 	UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:CellIdentifier];

// 	if (!cell) {
// 		cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:CellIdentifier];
// 	}

// 	NSDate *date = _objects[indexPath.row];
// 	cell.textLabel.text = date.description;
// 	return cell;
// }

// - (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
// 	[_objects removeObjectAtIndex:indexPath.row];
// 	[tableView deleteRowsAtIndexPaths:@[ indexPath ] withRowAnimation:UITableViewRowAnimationAutomatic];
// }

// #pragma mark - Table View Delegate

// - (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
// 	[tableView deselectRowAtIndexPath:indexPath animated:YES];
// }

@end
