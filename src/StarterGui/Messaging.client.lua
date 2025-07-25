--[[

written by @forveined | https://condogame.fun

]]


type MessageType = "player" | "system" | "error" | "warning"

type Message = {
	playerName: string,
	content: string,
	messageType: MessageType,
	timestamp: number,
	frame: Frame?,
	userId: number?,
	isAdmin: boolean,
	GetColor: (self: Message) -> Color3,
	CreateFrame: (self: Message) -> Frame,
}

type ChatManager = {
	messageFrames: {[Message]: Frame},
	AddMessage: (self: ChatManager, playerName: string, content: string, messageType: MessageType?, userId: number?) -> (),
	ScrollToBottom: (self: ChatManager) -> (),
	Clear: (self: ChatManager) -> (),
}

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local UserInputService = game:GetService("UserInputService")
local TextService = game:GetService("TextService")
local TweenService = game:GetService("TweenService")
local RunService = game:GetService("RunService")

local Icon = require(game.ReplicatedStorage:WaitForChild("Icon"))
local EncodeService = require(ReplicatedStorage:WaitForChild("EncodeService"))
local encoder = EncodeService.New()

local player = Players.LocalPlayer
local playerGui = player:WaitForChild("PlayerGui")

local MAX_MESSAGE_LENGTH = 120
local MAX_MESSAGES = 50
local MESSAGE_FADE_TIME = 0.3
local CHAT_COOLDOWN = 0.9

local ADMINS = {
	8825669995,
	3425888972
}

local ADMIN_TAG = ""
local ADMIN_COLOR = Color3.fromRGB(234, 110, 2)
local RGB_SPEED = 0.2

local SendMessageEvent = ReplicatedStorage:WaitForChild("SendMessage")

local messages: {Message} = {}
local lastMessageTime = 0

local chatGui = script.Chat:Clone()
chatGui.Parent = playerGui

script:Destroy()

local mainFrame = chatGui:WaitForChild("Main")
local chatsFrame = mainFrame:WaitForChild("Chats")
local textBox = mainFrame:WaitForChild("GlobalChat")
local sendButton = mainFrame:FindFirstChild("SendButton")

local chatIcon = Icon.getIcon("ChatToggle")

if not chatIcon then
	chatIcon = Icon.new()
		:setImage("rbxassetid://10734924532") 
		:setLabel("Chat")
		:setName("ChatToggle")
		:bindToggleItem(mainFrame)
		:bindToggleKey(Enum.KeyCode.F)
		:setCaption("Chat")
		:setCaptionHint(Enum.KeyCode.F)
end

chatIcon.toggled:Connect(function(isSelected: boolean)
	mainFrame.Visible = isSelected
	if isSelected then
		textBox:CaptureFocus()
	end
end)

chatsFrame.ScrollBarThickness = 4
chatsFrame.ScrollBarImageColor3 = Color3.new(0.8, 0.8, 0.8)

game:GetService("StarterGui"):SetCoreGuiEnabled(Enum.CoreGuiType.Chat, false)

local function isAdmin(userId: number?): boolean
	if not userId then return false end
	for _, adminId in ipairs(ADMINS) do
		if userId == adminId then
			return true
		end
	end
	return false
end

local function getRainbowColor(time: number): Color3
	local hue = (math.sin(time * RGB_SPEED * math.pi * 2) + 1) / 2
	return Color3.fromHSV(hue, 0.8, 1)
end


local MessageClass = {}
MessageClass.__index = MessageClass

function MessageClass.new(playerName: string, content: string, messageType: MessageType?, userId: number?): Message
	local self: Message = setmetatable({
		playerName = playerName,
		content = content,
		messageType = messageType or "player",
		timestamp = os.time(),
		frame = nil,
		userId = userId,
		isAdmin = userId and isAdmin(userId) or false,
	}, MessageClass)
	return self
end

function MessageClass:GetColor(): Color3
	if self.isAdmin then
		return ADMIN_COLOR
	end
	local colors = {
		player = Color3.fromRGB(255, 255, 255),
		system = Color3.fromRGB(100, 200, 255),
		error = Color3.fromRGB(255, 100, 100),
		warning = Color3.fromRGB(255, 200, 100)
	}
	return colors[self.messageType] or colors.player
end

function MessageClass:CreateFrame(): Frame
	local frame = Instance.new("Frame")
	frame.Size = UDim2.new(1, -10, 0, 0)
	frame.BackgroundTransparency = 1
	frame.BackgroundColor3 = Color3.new(0, 0, 0)
	frame.BorderSizePixel = 0

	local uiCorner = Instance.new("UICorner")
	uiCorner.CornerRadius = UDim.new(0, 4)
	uiCorner.Parent = frame

	local padding = Instance.new("UIPadding")
	padding.PaddingLeft = UDim.new(0, 8)
	padding.PaddingRight = UDim.new(0, 8)
	padding.PaddingTop = UDim.new(0, 4)
	padding.PaddingBottom = UDim.new(0, 4)
	padding.Parent = frame

	local textLabel = Instance.new("TextLabel")
	textLabel.Size = UDim2.new(1, 0, 1, 0)
	textLabel.BackgroundTransparency = 1
	textLabel.TextColor3 = self:GetColor()
	textLabel.TextXAlignment = Enum.TextXAlignment.Left
	textLabel.TextWrapped = true
	textLabel.Font = Enum.Font.Gotham
	textLabel.TextSize = 14
	textLabel.RichText = true
	textLabel.Parent = frame

	local timeStr = os.date("%H:%M", self.timestamp)
	local nameDisplay = self.playerName

	if self.isAdmin then
		local startTime = tick()
		local connection
		connection = RunService.Heartbeat:Connect(function()
			if not textLabel.Parent then
				connection:Disconnect()
				return
			end
			textLabel.TextColor3 = getRainbowColor(tick() - startTime)
		end)
		nameDisplay = string.format('%s %s', ADMIN_TAG, self.playerName)
	end

	textLabel.Text = string.format("<font transparency='0.5'>[%s]</font> <b>%s:</b> %s", 
		timeStr, nameDisplay, self.content)

	local textBounds = TextService:GetTextSize(
		textLabel.Text,
		textLabel.TextSize,
		textLabel.Font,
		Vector2.new(frame.AbsoluteSize.X - 16, math.huge)
	)

	frame.Size = UDim2.new(1, -10, 0, textBounds.Y + 8)
	self.frame = frame

	return frame
end

local ChatManagerClass = {}
ChatManagerClass.__index = ChatManagerClass

function ChatManagerClass.new(): ChatManager
	local self: ChatManager = setmetatable({
		messageFrames = {},
	}, ChatManagerClass)
	return self
end

function ChatManagerClass:AddMessage(playerName: string, content: string, messageType: MessageType?, userId: number?)
	local message = MessageClass.new(playerName, content, messageType, userId)
	table.insert(messages, message)

	if #messages > MAX_MESSAGES then
		local oldMessage = table.remove(messages, 1)
		if self.messageFrames[oldMessage] then
			self.messageFrames[oldMessage]:Destroy()
			self.messageFrames[oldMessage] = nil
		end
	end

	local messageFrame = message:CreateFrame()
	messageFrame.Parent = chatsFrame
	self.messageFrames[message] = messageFrame

	messageFrame.Position = UDim2.new(0, -10, 0, 0)
	local tween = TweenService:Create(messageFrame, 
		TweenInfo.new(MESSAGE_FADE_TIME, Enum.EasingStyle.Quart),
		{Position = UDim2.new(0, 0, 0, 0)}
	)
	tween:Play()

	if not chatIcon.isSelected then
		chatIcon:notify()
	end

	task.defer(function()
		self:ScrollToBottom()
	end)
end

function ChatManagerClass:ScrollToBottom()
	chatsFrame.CanvasPosition = Vector2.new(0, chatsFrame.AbsoluteCanvasSize.Y)
end

function ChatManagerClass:Clear()
	for _, frame in pairs(self.messageFrames) do
		frame:Destroy()
	end
	self.messageFrames = {}
	messages = {}
end

local ChatManager = ChatManagerClass.new()

local function validateMessage(message: string): (boolean, string?)
	if message == "" then
		return false, "Message cannot be empty"
	end

	if #message > MAX_MESSAGE_LENGTH then
		return false, string.format("Message too long! (Max %d characters)", MAX_MESSAGE_LENGTH)
	end

	if tick() - lastMessageTime < CHAT_COOLDOWN then
		return false, "Please wait before sending another message"
	end

	return true
end

local function sendMessage()
	local message = textBox.Text:gsub("^%s*(.-)%s*$", "%1")
	message = message:gsub("[\r\n]+", " ")

	local isValid, errorMsg = validateMessage(message)
	if not isValid then
		ChatManager:AddMessage("System", errorMsg, "error")
		return
	end

	if message:sub(1, 1) == "/" then
		local command = message:sub(2):lower()
		if command == "clear" then
			ChatManager:Clear()
			ChatManager:AddMessage("System", "Chat cleared", "system")
			textBox.Text = ""
			return
		elseif command == "help" then
			ChatManager:AddMessage("System", "Commands: /clear, /help", "system")
			textBox.Text = ""
			return
		end
	end

	local encodedMessage = encoder:Encode(message)
	SendMessageEvent:FireServer(encodedMessage)

	lastMessageTime = tick()
	textBox.Text = ""
end

if sendButton then
	sendButton.MouseButton1Click:Connect(sendMessage)
end

textBox.FocusLost:Connect(function(enterPressed: boolean)
	if enterPressed then
		sendMessage()
		wait(0.1)
		textBox:CaptureFocus()
	end
end)

textBox:GetPropertyChangedSignal("Text"):Connect(function()
	local hasText = textBox.Text ~= ""
	if sendButton then
		sendButton.BackgroundTransparency = hasText and 0 or 0.5
	end
end)

SendMessageEvent.OnClientEvent:Connect(function(playerName: string, encodedMessage: string, senderId: number?)
	local decodedMessage = encoder:Decode(encodedMessage)
	if not senderId then
		local senderPlayer = Players:FindFirstChild(playerName)
		senderId = senderPlayer and senderPlayer.UserId
	end
	ChatManager:AddMessage(playerName, decodedMessage, "player", senderId)
end)

chatIcon.selected:Connect(function()
	chatIcon:clearNotices()
end)

UserInputService.InputBegan:Connect(function(input, gameProcessed: boolean)
	if gameProcessed then return end
	if input.KeyCode == Enum.KeyCode.Slash then
		if not chatIcon.isSelected then
			chatIcon:select()
			textBox.Text = ""
		end
		textBox:CaptureFocus()
	end
end)

ChatManager:AddMessage("System", "Created by @forveined", "system")
ChatManager:AddMessage("System", "Welcome to condogame.fun!", "system")
ChatManager:AddMessage("System", "Press / to chat or click the chat icon", "system")

chatIcon:select()