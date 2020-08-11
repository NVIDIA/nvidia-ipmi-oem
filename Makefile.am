SUBDIRS = include

AM_CXXFLAGS = -I$(abs_srcdir) -I$(abs_srcdir)/include

libnvipmioemcmdsdir = $(libdir)/ipmid-providers
libnvipmioemcmds_LTLIBRARIES = libnvipmioemcmds.la
libnvipmioemcmds_la_SOURCES = oem_global_handler.hpp \
							  oem_global_handler.cpp \
                              oem_chassis_handler.hpp \
                              oem_chassis_handler.cpp
libnvipmioemcmds_la_LDFLAGS = $(SYSTEMD_LIBS) \
         	                  $(SDBUSPLUS_LIBS) \
            	              $(LIBIPMID_LIBS) \
                	          $(LIBIPMID_HOST_LIBS) \
                    	      $(PHOSPHOR_LOGGING_LIBS) \
                        	  -shared

libnvipmioemcmds_la_CXXFLAGS = $(SYSTEMD_CFLAGS) \
        	                   $(SDBUSPLUS_CFLAGS) \
            	               $(LIBIPMID_CFLAGS) \
                	           $(LIBIPMID_HOST_CFLAGS) \
                    	       $(PHOSPHOR_LOGGING_CFLAGS) \
                        	   $(AM_CXXFLAGS)
