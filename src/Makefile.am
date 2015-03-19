lib_LTLIBRARIES = \
    libgrapple.la

libgrapple_la_SOURCES = \
    dynstring.c \
    grapple_callback.c \
    grapple_callback_dispatcher.c \
    grapple_certificate.c \
    grapple_client.c \
    grapple_client_thread.c \
    grapple_comms.c \
    grapple_comms_api.c \
    grapple_confirm.c \
    grapple_connection.c \
    grapple_error.c \
    grapple_failover.c \
    grapple_group.c \
    grapple_lobby.c \
    grapple_lobbycallback.c \
    grapple_lobbyclient.c \
    grapple_lobbyclient_thread.c \
    grapple_lobbyconnection.c \
    grapple_lobbyerror.c \
    grapple_lobbygame.c \
    grapple_lobbymessage.c \
    grapple_message.c \
    grapple_queue.c \
    grapple_server.c \
    grapple_server_thread.c \
    grapple_thread.c \
    grapple_tools.c \
    grapple_variable.c \
    socket.c \
    tools.c \
    ufc-crypt/crypt.c \
    ufc-crypt/crypt_util.c

libgrappleincludedir = $(includedir)/grapple
libgrappleinclude_HEADERS = \
    grapple.h \
    grapple_callback.h \
    grapple_certificate.h \
    grapple_client.h \
    grapple_defines.h \
    grapple_error.h \
    grapple_lobby.h \
    grapple_lobbyclient.h \
    grapple_lobby_types.h \
    grapple_message.h \
    grapple_protocols.h \
    grapple_server.h \
    grapple_types.h \
    grapple_tools.h

noinst_HEADERS = \
    dynstring.h \
    grapple_callback_internal.h \
    grapple_callback_dispatcher.h \
    grapple_client_internal.h \
    grapple_client_thread.h \
    grapple_comms.h \
    grapple_comms_api.h \
    grapple_configure_substitute.h \
    grapple_confirm.h \
    grapple_connection.h \
    grapple_failover.h \
    grapple_group.h \
    grapple_group_internal.h \
    grapple_enums.h \
    grapple_error_internal.h \
    grapple_internal.h \
    grapple_lobby_internal.h \
    grapple_lobbyclient_thread.h \
    grapple_lobbyconnection.h \
    grapple_lobbycallback.h \
    grapple_lobbyerror.h \
    grapple_lobbymessage.h \
    grapple_lobbygame.h \
    grapple_message_internal.h \
    grapple_queue.h \
    grapple_server_internal.h \
    grapple_server_thread.h \
    grapple_structs.h \
    grapple_thread.h \
    grapple_variable.h \
    prototypes.h \
    socket.h \
    tools.h \
    ufc-crypt/crypt.h \
    ufc-crypt/crypt_util.h


libgrapple_la_LDFLAGS = \
    -no-undefined           \
    -release $(LT_RELEASE)  \
    -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
