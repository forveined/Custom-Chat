--[[

written by @forveined | https://condogame.fun

]]


local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Players = game:GetService("Players")
local ChatEvent = ReplicatedStorage:WaitForChild("SendMessage")
local EncodeService = require(ReplicatedStorage:WaitForChild("EncodeService"))
local encoder = EncodeService.New()

ChatEvent.OnServerEvent:Connect(function(player: Player, encodedMessage: string)
	if type(encodedMessage) ~= "string" or encodedMessage == "" then
		return
	end
	if encodedMessage:len() > 2000 then
		player:Kick("nice try!")
		return
	end
	local success, decodedMessage = pcall(function()
		return encoder:Decode(encodedMessage)
	end)
	if not success then
		return
	end
	if player.Character and player.Character:FindFirstChild("Head") then
		game:GetService("Chat"):Chat(player.Character.Head, decodedMessage, Enum.ChatColor.White)
	end
	ChatEvent:FireAllClients(player.Name, encodedMessage, player.UserId)
end)