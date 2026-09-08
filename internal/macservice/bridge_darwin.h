#include <stddef.h>

void *openuem_app_service_open(const char *bundle_path, const char *executable_path,
                             const char *identifier, const char *plist_name);
int openuem_app_service_status(void *service);
int openuem_app_service_register(void *service);
void openuem_app_service_close(void *service);
