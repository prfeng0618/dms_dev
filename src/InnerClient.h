#ifndef __INNER_CLIENT_H__
#define __INNER_CLIENT_H__

#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <vector>
#include "utils.h"

#define STD_PORT       8090
#define PT_HELO         0x01
#define PT_BYE          0x02
#define PT_ACTION       0x0A
#define MAX_PACKET_SIZE  1024
#define HEADER_SIZE      8
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - HEADER_SIZE)

class CAddress
{
private:
    struct sockaddr_in m_Addr;

public:
    CAddress(int Port = STD_PORT)
    {
        m_Addr.sin_family = AF_INET;
        m_Addr.sin_port = htons(Port);
        m_Addr.sin_addr.s_addr = INADDR_ANY;
        memset(m_Addr.sin_zero, '\0', sizeof m_Addr.sin_zero);
    }

    CAddress(const char *Address, int Port = STD_PORT)
    {
        m_Addr.sin_port = htons(Port);
		
		/*
	        struct hostent *h;
	        if (Address == NULL || (h=gethostbyname(Address)) == NULL)
	        {
	            if (Address != NULL)
			        LOGE("Error: Get host by name");

	            m_Addr.sin_addr.s_addr  = INADDR_ANY;
	            m_Addr.sin_family       = AF_INET;
	        }
	        else
	        {
	            m_Addr.sin_family = h->h_addrtype;
	            m_Addr.sin_addr = *((struct in_addr *)h->h_addr);
	        }
	        */
	        
		m_Addr.sin_addr.s_addr	= INADDR_ANY;
		m_Addr.sin_family		= AF_INET;	     
        memset(m_Addr.sin_zero, '\0', sizeof m_Addr.sin_zero);
    }

    void SetPort(int port)
    {
        m_Addr.sin_port = htons(port);
    }

    const sockaddr *GetAddress()
    {
        return ((struct sockaddr *)&m_Addr);
    }

    bool Bind(int Sockfd)
    {
        return (bind(Sockfd, (struct sockaddr *)&m_Addr, sizeof m_Addr) == 0);
    }
};

class CPacket
{
/*   Base class that implements a single event packet.

     - Generic packet structure (maximum 1024 bytes per packet)
     - Header is 8 bytes long, so 1016 bytes available for payload

         -----------------------------
         | -H1 Signature ("MZGS")    | - 4  x CHAR                4B
         | -H2 PacketType            | - 1  x UNSIGNED SHORT      2B
         | -H3 Payload size          | - 1  x UNSIGNED SHORT      2B
         |---------------------------|
         | -P1 payload               | -
         -----------------------------
*/
public:
    CPacket()
    {
        m_PacketType = 0;
    }
    virtual ~CPacket() { }

    bool Send(int Socket, CAddress &Addr)
    {
        if (m_Payload.size() == 0)
            ConstructPayload();
        bool SendSuccessfull = true;
        int NbrOfPackages = (m_Payload.size() / MAX_PAYLOAD_SIZE) + 1;
        int Send = 0;
        int Sent = 0;
        int Left = m_Payload.size();
        for (int Package = 1; Package <= NbrOfPackages; Package++)
        {
            if (Left > MAX_PAYLOAD_SIZE)
            {
                LOGE("Error: Large payload");
                return false;
                Send = MAX_PAYLOAD_SIZE;
                Left -= Send;
            }
            else
            {
                Send = Left;
                Left = 0;
            }

            ConstructHeader(m_PacketType, NbrOfPackages, Package, Send, m_Header);
            char t[MAX_PACKET_SIZE];
            int i, j;
            for (i = 0; i < HEADER_SIZE; i++)
                t[i] = m_Header[i];

            for (j = 0; j < Send; j++)
                t[(HEADER_SIZE + j)] = m_Payload[j + Sent];

            int rtn = sendto(Socket, t, (HEADER_SIZE + Send), 0, Addr.GetAddress(), sizeof(struct sockaddr));
            if (rtn != (HEADER_SIZE + Send))
                SendSuccessfull = false;

            Sent += Send;
        }
        return SendSuccessfull;
    }

protected:
    char            m_Header[HEADER_SIZE];
    unsigned short  m_PacketType;

    std::vector<char> m_Payload;

    static void ConstructHeader(int PacketType, int NumberOfPackets, int CurrentPacket, unsigned short PayloadSize, char *Header)
    {
        sprintf(Header, "MZGS");
        for (int i = 4; i < HEADER_SIZE; i++)
            Header[i] = 0;

        if (CurrentPacket == 1)
        {
            Header[4]  = ((PacketType & 0xff00) >> 8);
            Header[5]  =  (PacketType & 0x00ff);
        }

        Header[6] = ((PayloadSize & 0xff00) >> 8);
        Header[7] =  (PayloadSize & 0x00ff);
    }

    virtual void ConstructPayload() { }
};

class CPacketACTION : public CPacket
{
/************************************************************************/
/* Payload format                                                       */
/* %s - action message                                                  */
/************************************************************************/
private:
    unsigned char     m_ActionType;
    std::vector<char> m_Action;
public:
    CPacketACTION(const char *Action)
    {
        m_PacketType = PT_ACTION;

        unsigned int len = strlen(Action);
        for (unsigned int i = 0; i < len; i++)
            m_Action.push_back(Action[i]);
    }

    virtual void ConstructPayload()
    {
        m_Payload.clear();

        for (unsigned int i = 0; i < m_Action.size(); i++)
            m_Payload.push_back(m_Action[i]);

        m_Payload.push_back('\0');
    }

    virtual ~CPacketACTION() { }
};

class CClient
{
private:
    CAddress      m_Addr;
    int           m_Socket;
    unsigned int  m_UID;

public:
    CClient(const char *IP = "127.0.0.1", int Port = 9777, int Socket = -1)
    {
        m_Addr = CAddress(IP, Port);
        if (Socket == -1)
            m_Socket = socket(AF_INET, SOCK_DGRAM, 0);
        else
            m_Socket = Socket;

    }

    void SendACTION(const char *ActionMessage)
    {
        if (m_Socket < 0) {
            LOGE("no sockect");
            return;
        }

        CPacketACTION action(ActionMessage);
        action.Send(m_Socket, m_Addr);
    }

    char* GetStatus(char *buffer)
    {
        if (m_Socket < 0)
            return NULL;
        int packetSize = recvfrom(m_Socket, (char*)buffer, (size_t)1024, 0,(struct sockaddr*)NULL, NULL);
        return buffer;
    }
	
	 ~CClient( )
	{
		if (m_Socket != -1){
			close(m_Socket);
		}
	}

};

#endif //__INNER_CLIENT_H__
