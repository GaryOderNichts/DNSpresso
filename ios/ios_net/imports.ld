PROVIDE(printf = 0x123ccfbc);

PROVIDE(memcpy = 0x123e2a24);
PROVIDE(memset = 0x123e2ac0);
PROVIDE(strncpy = 0x123e3534);
PROVIDE(snprintf = 0x123e34cc);

PROVIDE(IOS_CreateThread = 0x123e4254);
PROVIDE(IOS_StartThread = 0x123e428c);
PROVIDE(IOS_GetThreadPriority = 0x123e42a4);
PROVIDE(IOS_CreateMessageQueue = 0x123e42b4);
PROVIDE(IOS_DestroyMessageQueue = 0x123e42bc);
PROVIDE(IOS_ReceiveMessage = 0x123e42d4);
PROVIDE(IOS_Alloc = 0x123e438c);
PROVIDE(IOS_AllocAligned = 0x123e4394);
PROVIDE(IOS_Free = 0x123e439c);
PROVIDE(IOS_Open = 0x123e43ec);
PROVIDE(IOS_Close = 0x123e43f4);
PROVIDE(IOS_Ioctl = 0x123e4414);
PROVIDE(IOS_Ioctlv = 0x123e441c);
PROVIDE(IOS_GetAbsTime64 = 0x123e433c);
PROVIDE(IOS_GetAbsTimeCalendar = 0x123e4334);
PROVIDE(IOS_CreateSemaphore = 0x123e450c);
PROVIDE(IOS_WaitSemaphore = 0x123e4514);
PROVIDE(IOS_SignalSemaphore = 0x123e451c);
PROVIDE(IOS_DestroySemaphore = 0x123e4524);
PROVIDE(IOS_ResourceReply = 0x123e449c);
PROVIDE(IOS_Shutdown = 0x123e45e4);

PROVIDE(currentNetThread = 0x1280849c);
