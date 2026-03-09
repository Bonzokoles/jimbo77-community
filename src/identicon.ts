
export async function generateIdenticon(seed: string): Promise<string> {
    const msgBuffer = new TextEncoder().encode(seed);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));

    const r = hashArray[0];
    const g = hashArray[1];
    const b = hashArray[2];
    const color = `rgb(${r},${g},${b})`;
    const bg = '#f0f0f0';
    
    const rects: string[] = [];
    let idx = 3; // start after color bytes

    for (let row = 0; row < 5; row++) {
        // Build a row of 5 cells (0,1,2, 3=1, 4=0)
        const rowData: boolean[] = [];
        for (let col = 0; col < 3; col++) {
            const byte = hashArray[idx % hashArray.length];
            rowData.push(byte % 2 === 0);
            idx++;
        }
        
        const cells = [rowData[0], rowData[1], rowData[2], rowData[1], rowData[0]];

        for (let col = 0; col < 5; col++) {
            if (cells[col]) {
                rects.push(`<rect x="${col * 10}" y="${row * 10}" width="10" height="10" fill="${color}" />`);
            }
        }
    }

    const svgContent = `
    <svg width="100" height="100" viewBox="0 0 50 50" xmlns="http://www.w3.org/2000/svg">
        <rect width="50" height="50" fill="${bg}" />
        ${rects.join('')}
    </svg>
    `.trim().replace(/\s+/g, ' ');

    const base64 = btoa(svgContent);
    return `data:image/svg+xml;base64,${base64}`;
}
