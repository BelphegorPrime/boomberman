export function corruptJsonString(json: string): string {
  const corruptions = [
    (str: string) => str.replace(/:/, ''), // Remove colon
    (str: string) => str.replace(/["']/g, ''), // Strip quotes
    (str: string) => str.replace(/,(\s*[}\]])/, '$1'), // Remove comma before object/array end
    (str: string) => str.slice(0, -1), // Chop off last character
    (str: string) => str + ',', // Add dangling comma
    (str: string) => str.replace(/\}/, '}}'), // Extra brace
    (str: string) => str.replace(/\{/, ''), // Remove opening brace
  ];

  const random = corruptions[Math.floor(Math.random() * corruptions.length)];
  return random(json);
}
