/*
    Grapple - A fully featured network layer with a simple interface
    Copyright (C) 2006 Michael Simms

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    Michael Simms
    michael@linuxgamepublishing.com
*/

#include "grapple_configure_substitute.h"

#include "grapple_error.h"
#include "grapple_error_internal.h"
#include "grapple_structs.h"

//A local global variable that stores the last grapple error
static grapple_error global_error;

//Set the error
void grapple_client_error_set(internal_client_data *client,grapple_error error)
{
  client->last_error=error;
}

void grapple_server_error_set(internal_server_data *server,grapple_error error)
{
  server->last_error=error;
}

void grapple_error_set(grapple_error error)
{
  global_error=error;
}

grapple_error grapple_error_get()
{
  grapple_error returnval;

  returnval=global_error;

  //Now wipe the last error
  global_error=GRAPPLE_NO_ERROR;

  return returnval;
}

//Set a text representation of the error
const char *grapple_error_text(grapple_error error)
{
  switch (error)
    {
    case GRAPPLE_NO_ERROR:
      return "No error";
      break;
    case GRAPPLE_ERROR_NOT_INITIALISED:
      return "Attempt to use function before initialisation";
      break;
    case GRAPPLE_ERROR_SERVER_CONNECTED:
      return "Server is already connected";
      break;
    case GRAPPLE_ERROR_SERVER_NOT_CONNECTED:
      return "Server is not connected";
      break;
    case GRAPPLE_ERROR_SERVER_NOT_CONNECTABLE:
      return "Server is not connectable";
      break;
    case GRAPPLE_ERROR_CLIENT_CONNECTED:
      return "Client is already connected";
      break;
    case GRAPPLE_ERROR_CLIENT_NOT_CONNECTED:
      return "Client is not connected";
      break;
    case GRAPPLE_ERROR_ADDRESS_NOT_SET:
      return "Connection address not set";
      break;
    case GRAPPLE_ERROR_PORT_NOT_SET:
      return "Port number not set";
      break;
    case GRAPPLE_ERROR_NAME_NOT_SET:
      return "Name not set";
      break;
    case GRAPPLE_ERROR_NAME_NOT_UNIQUE:
      return "Name not unique";
      break;
    case GRAPPLE_ERROR_SESSION_NOT_SET:
      return "Session name not set";
      break;
    case GRAPPLE_ERROR_PROTOCOL_NOT_SET:
      return "Protocol not set";
      break;
    case GRAPPLE_ERROR_CANNOT_CONNECT:
      return "Cannot connect to server";
      break;
    case GRAPPLE_ERROR_NO_SUCH_USER:
      return "No such user";
      break;
    case GRAPPLE_ERROR_SERVER_CANNOT_BIND_SOCKET:
      return "Server cannot bind socket";
      break;
    case GRAPPLE_ERROR_NO_SUCH_GROUP:
      return "No such group";
      break;
    case GRAPPLE_ERROR_NO_SUCH_VARIABLE:
      return "No such variable";
      break;
    case GRAPPLE_ERROR_INCORRECT_VARIABLE_TYPE:
      return "Incorrect variable type";
      break;      
    case GRAPPLE_ERROR_BAD_PASSWORD:
      return "Invalid password";
      break;
    case GRAPPLE_ERROR_INSUFFICIENT_SPACE:
      return "Insufficient space";
      break;      
    case GRAPPLE_ERROR_NO_MESSAGES:
      return "No messages available";
      break;
    case GRAPPLE_ERROR_NO_SUCH_GAME:
      return "No such game";
      break;
    }

  return "Unknown error";
}
