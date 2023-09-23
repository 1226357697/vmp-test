#include "plugin.h"
#include <string_view>
#include <list>
#include "pass_mem_check.h"

const int MENU_ENTRY_SAVE_ENVP  = 0;
const std::string_view MENU_ENTRY_SAVE_ENVP_NAME = u8"保存环境";
const int MENU_ENTRY_START_MEMEHCK = 1;
const std::string_view MENU_ENTRY_START_MEMEHCK_NAME = u8"开启过内存检测";
const int MENU_ENTRY_CLOSE_MEMEHCK = 2;
const std::string_view MENU_ENTRY_CLOSE_MEMEHCK_NAME = u8"关闭过内存检测";

using cb_menu_handle = void(*)(CBTYPE cbType, PLUG_CB_MENUENTRY* info);

void cb_save_environment(CBTYPE cbType, PLUG_CB_MENUENTRY* info);
void cb_start_bypass_memory_check(CBTYPE cbType, PLUG_CB_MENUENTRY* info);
void cb_close_bypass_memory_check(CBTYPE cbType, PLUG_CB_MENUENTRY* info);

struct MenuItemInfo
{
    int EntryId;
    std::string_view EntryName;
	cb_menu_handle Handle;
};

MenuItemInfo g_menuItems[] = {
	{MENU_ENTRY_SAVE_ENVP, MENU_ENTRY_SAVE_ENVP_NAME, &cb_save_environment},
	{MENU_ENTRY_START_MEMEHCK, MENU_ENTRY_START_MEMEHCK_NAME, &cb_start_bypass_memory_check},
	{MENU_ENTRY_CLOSE_MEMEHCK, MENU_ENTRY_CLOSE_MEMEHCK_NAME, &cb_close_bypass_memory_check},
};

static void registerMenuItem()
{
	for (const auto& item : g_menuItems)
	{
		_plugin_menuaddentry(hMenu, item.EntryId, item.EntryName.data());
	}

}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
}

//Do GUI/Menu related things here.
void pluginSetup()
{
	registerMenuItem();
    
}


PLUG_EXPORT
void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY * info)
{
	const auto& iter = std::find_if(
		std::begin(g_menuItems),
		std::end(g_menuItems),
		[info](const MenuItemInfo& itemInfo)->bool {
			return std::equal_to()(info->hEntry, itemInfo.EntryId);
		}
	);

	if (iter != std::end(g_menuItems))
	{
		iter->Handle(cbType, info);
	}

}


void cb_save_environment(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	Section sect;
	std::list<Section> sections;
	sect.virtual_address = (void*)0x0072B000;
	sect.virtual_size = 0x00267000;
	sections.push_back(sect);
	save_check_section(sections);
	dprintf("cb_save_environment");
}

void cb_start_bypass_memory_check(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	cb_save_environment(CB_LAST, nullptr);
	initialize_cheat_handle();
	dprintf("cb_start_bypass_memory_check");

}

void cb_close_bypass_memory_check(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	destory_cheat_handle();
	dprintf("cb_close_bypass_memory_check");
}