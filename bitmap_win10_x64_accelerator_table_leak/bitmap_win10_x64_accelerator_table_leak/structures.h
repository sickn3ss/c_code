#define STATUS_SUCCESS 0x00000000
typedef void** PPVOID;

typedef struct _tagSERVERINFO {
	UINT64 pad;
	UINT64 cbHandleEntries;
} SERVERINFO, *PSERVERINFO;

typedef struct _HANDLEENTRY {
	PVOID pHeader;	// Pointer to the Object
	PVOID pOwner;	// PTI or PPI
	UCHAR bType;	// Object handle type
	UCHAR bFlags;	// Flags
	USHORT wUniq;	// Access count
} HANDLEENTRY, *PHANDLEENTRY;

typedef struct _SHAREDINFO {
	PSERVERINFO psi;
	PHANDLEENTRY aheList;
} SHAREDINFO, *PSHAREDINFO;