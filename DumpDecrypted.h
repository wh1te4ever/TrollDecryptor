@interface DumpDecrypted : NSObject {
	char decryptedAppPathStr[PATH_MAX];
	char *filename;
	char *appDirName;
	char *appDirPath;
}

@property (assign) NSString *appPath;
@property (assign) NSString *docPath;

-(id)initWithPathToBinary:(NSString *)pathToBinary;
-(void) createIPAFile:(pid_t)pid;
-(BOOL)dumpDecryptedImage:(const struct mach_header *)image_mh fileName:(const char *)encryptedImageFilenameStr image:(int)imageNum task:(vm_map_t)targetTask;
-(NSString *)IPAPath;
-(void)IPAServer:(int)listenPort;
-(int)getSocketForPort:(int)listenPort;
-(NSDictionary *)getIPAddresses;

	@end
