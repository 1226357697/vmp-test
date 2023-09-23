#include "plugin.h"
#include <assert.h>
#include "VmpFixImport.h"

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	Initialize();
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
	Destory();
}

//Do GUI/Menu related things here.
void pluginSetup()
{
   
}

// [��ѡ����] �˵������ʱ, �͵����������
extern "C" __declspec(dllexport)
void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY * info)
{
	switch (info->hEntry)
	{
	case 0:
	{
		VmpFixImport();
		break;
	}
	default:
		assert(0);
		break;
	}
}
