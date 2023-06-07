include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=vcs-device-identity
PKG_VERSION:=2.0
PKG_RELEASE:=1

# Source settings (i.e. where to find the source codes)
# This is a custom variable, used below
SOURCE_DIR:=/code/mypackages/vcs-device-identity/src

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/vcs-device-identity
  SECTION:=vcs
  CATEGORY:=VCS
  DEPENDS:=+libpcap
  TITLE:=VCS Device Identity!
endef

# Package description; a more verbose description on what our package does
define Package/vcs-device-identity/description
  A VCS Device Identity - Application.
endef

# Package preparation instructions; create the build directory and copy the source code. 
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
		mkdir -p $(PKG_BUILD_DIR)
		cp $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
		$(Build/Patch)
endef

TARGET_CFLAGS:=$(filter-out -Wformat -Werror=format-security,$(TARGET_CFLAGS))
TARGET_CFLAGS += -fstack-protector-all -fPIE -g -ggdb -Wall -Wno-format -DVERSION=\"$(PKG_VERSION)\"
TARGET_LDFLAGS += -Wl,-z,relro -pie

# Package build instructions; invoke the target-specific compiler to first compile the source file, and then to link the file into the final executable
define Build/Compile
		$(MAKE) -C $(PKG_BUILD_DIR) \
			CC="$(TARGET_CC)" \
			USE_CFLAGS="$(TARGET_CFLAGS)" \
			USE_LDFLAGS="$(TARGET_LDFLAGS)"
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/vcs-device-identity/install
		$(INSTALL_DIR) $(1)/usr/bin
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/vcs-device-identity $(1)/usr/bin
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/database.fp $(1)/usr/bin
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/vcs-device-manager $(1)/usr/bin
		$(INSTALL_BIN) $(PKG_BUILD_DIR)/detect_connected_client.sh $(1)/usr/bin
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/monitor-client.conf $(1)/usr/bin
		$(INSTALL_DATA) $(PKG_BUILD_DIR)/dhcpclient.log $(1)/usr/bin

		$(INSTALL_DIR) $(1)/etc/init.d
	    $(INSTALL_BIN) ./files/vcsdevicemanager.init $(1)/etc/init.d/vcsdevicemanager
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,vcs-device-identity))
