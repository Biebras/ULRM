﻿using LightReflectiveMirror.Endpoints;
using System;

namespace LightReflectiveMirror
{
    public partial class RelayHandler
    {
        /// <summary>
        /// Invoked when a client connects to this LRM server.
        /// </summary>
        /// <param name="clientId">The ID of the client who connected.</param>
        public void ClientConnected(int clientId)
        {
            int connections = Program.instance.GetConnections();
            if (connections >= Program.conf.MaxConnections)
            {
                Program.WriteLogMessage($"Cannot add client {clientId} because server already has {connections} connections.");
                Program.transport.ServerDisconnect(clientId);
            }
            
            _pendingAuthentication.Add(clientId);
            var buffer = _sendBuffers.Rent(1);
            int pos = 0;
            buffer.WriteByte(ref pos, (byte)OpCodes.AuthenticationRequest);
            Program.transport.ServerSend(clientId, 0, new ArraySegment<byte>(buffer, 0, pos));
            _sendBuffers.Return(buffer);
        }

        /// <summary>
        /// Handles the processing of data from a client.
        /// </summary>
        /// <param name="clientId">The client who sent the data</param>
        /// <param name="segmentData">The binary data</param>
        /// <param name="channel">The channel the client sent the data on</param>
        public async void HandleMessage(int clientId, ArraySegment<byte> segmentData, int channel)
        {
            OpCodes opcode = OpCodes.Default;
            
            try
            {
                var data = segmentData.Array;
                int pos = segmentData.Offset;

                opcode = (OpCodes)data.ReadByte(ref pos);

                if (_pendingAuthentication.Contains(clientId))
                {
                    if (opcode == OpCodes.AuthenticationResponse)
                    {
                        string authResponse = data.ReadString(ref pos);
                        string firebaseToken = data.ReadString(ref pos);

                        if (authResponse != Program.conf.AuthenticationKey)
                        {
                            Program.WriteLogMessage($"Client {clientId} sent wrong auth key! Removing from LRM node.");
                            Program.transport.ServerDisconnect(clientId);
                        }

                        // Check client's Firebase token
                        var authenticatedUniqueId = await _authenticator.AuthenticateClient(firebaseToken);
                        if (authenticatedUniqueId == null)
                        {
                            Program.WriteLogMessage($"Client {clientId} failed Firebase authentication! Removing from LRM node.");
                            Program.transport.ServerDisconnect(clientId);
                            return;
                        }
                        // Later retrieve firebase id from firebase token
                        string uniqueId = authenticatedUniqueId;
                        
                        // Check if the client is already connected to this node.
                        if (Program.instance.IsClientConnected(uniqueId))
                        {
                            Program.WriteLogMessage($"Client {clientId} is already connected to this node! Removing from LRM node.");
                            Program.transport.ServerDisconnect(clientId);
                            return;
                        }

                        _pendingAuthentication.Remove(clientId);
                        Program.instance.AssignUniqueId(uniqueId, clientId);
                        
                        int writePos = 0;
                        var sendBuffer = _sendBuffers.Rent(1);
                        sendBuffer.WriteByte(ref writePos, (byte)OpCodes.Authenticated);
                        Program.transport.ServerSend(clientId, 0, new ArraySegment<byte>(sendBuffer, 0, writePos));
                            
                        _sendBuffers.Return(sendBuffer);
                    }
                    return;
                }

                switch (opcode)
                {
                    case OpCodes.CreateRoom: // bruh
                        CreateRoom(clientId, data.ReadInt   (ref pos), 
                                             data.ReadString(ref pos), 
                                             data.ReadBool  (ref pos), 
                                             data.ReadString(ref pos), 
                                             data.ReadBool  (ref pos), 
                                             data.ReadString(ref pos), 
                                             data.ReadBool  (ref pos), 
                                             data.ReadInt   (ref pos),
                                             data.ReadInt   (ref pos),
                                             data.ReadString(ref pos));
                        break;
                    case OpCodes.RequestID:
                        SendClientID(clientId);
                        break;
                    case OpCodes.LeaveRoom:
                        LeaveRoom(clientId);
                        break;
                    case OpCodes.JoinServer:
                        JoinRoom(clientId, data.ReadString(ref pos), data.ReadBool(ref pos), data.ReadString(ref pos));
                        break;
                    case OpCodes.KickPlayer:
                        LeaveRoom(data.ReadInt(ref pos), clientId);
                        break;
                    case OpCodes.SendData:
                        ProcessData(clientId, data.ReadBytes(ref pos), channel, data.ReadInt(ref pos));
                        break;
                    case OpCodes.UpdateRoomData:
                        var plyRoom = _cachedClientRooms[clientId];

                        if (plyRoom == null || plyRoom.hostId != clientId)
                            return;

                        if (data.ReadBool(ref pos))
                            plyRoom.serverName = data.ReadString(ref pos);

                        if (data.ReadBool(ref pos))
                            plyRoom.serverData = data.ReadString(ref pos);

                        if (data.ReadBool(ref pos))
                            plyRoom.isPublic = data.ReadBool(ref pos);

                        if (data.ReadBool(ref pos))
                            plyRoom.maxPlayers = data.ReadInt(ref pos);

                        Endpoint.RoomsModified();
                        break;
                }
            }
            catch
            {
                // sent invalid data, boot them hehe
                Program.WriteLogMessage($"Client {clientId} sent bad data! Removing from LRM node. Last OpCode: {opcode}");
                Program.transport.ServerDisconnect(clientId);
            }
        }

        /// <summary>
        /// Invoked when a client disconnects from the relay.
        /// </summary>
        /// <param name="clientId">The ID of the client who disconnected</param>
        public void HandleDisconnect(int clientId) => LeaveRoom(clientId);
    }
}
