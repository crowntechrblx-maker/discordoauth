export default function handler(req, res) {
  res.status(200).json({
    status: "ok",
    service: "discord-roblox-link",
    timestamp: new Date().toISOString()
  });
}