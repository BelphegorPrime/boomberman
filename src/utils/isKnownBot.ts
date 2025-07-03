const knownBots = [
  /curl/i,
  /httpie/i,
  /wget/i,
  /python-requests/i,
  /python/i,
  /axios/i,
  /postman/i,
  /java/i,
  /libwww/i,
  /Go-http-client/i,
  /nikto/i,
  /nmap/i,
];

export function isKnownBot(userAgent: string = ''): boolean {
  return knownBots.some((pattern) => pattern.test(userAgent));
}
