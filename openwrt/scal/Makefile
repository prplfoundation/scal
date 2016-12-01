include $(TOPDIR)/rules.mk

PKG_NAME:=scal
PKG_VERSION:=$(shell git show -s --format=%cd --date=short)
PKG_RELEASE=1

PKG_FILE_DEPENDS:=$(CURDIR)/../..

PKG_LICENSE:=ISC
PKG_LICENSE_FILES:=

PKG_MAINTAINER:=Felix Fietkau <nbd@nbd.name>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/scal
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=System Configuration Access Layer
  DEPENDS:=+libubox +libubus
endef

define Package/scal-plugin-json
$(Package/scal)
  TITLE:=SCAL JSON data model backend
  DEPENDS:=+scal +libblobmsg-json +libjson-script +libuci
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	ln -s $(CURDIR)/../../.git $(PKG_BUILD_DIR)/
	(cd $(PKG_BUILD_DIR); git checkout .)
	$(Build/Patch)
endef

define Package/scal/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scald $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cli $(1)/usr/bin/scal-cli
endef

define Package/scal-plugin-json/install
	$(INSTALL_DIR) $(1)/usr/lib/scald
	$(CP) $(PKG_BUILD_DIR)/plugins/scapi_json.so $(1)/usr/lib/scald
endef

$(eval $(call BuildPackage,scal))
$(eval $(call BuildPackage,scal-plugin-json))
