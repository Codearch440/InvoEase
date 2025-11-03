const itemsDiv = document.getElementById("items");
const addItemBtn = document.getElementById("addItem");
const previewDiv = document.getElementById("preview");
const generateBtn = document.getElementById("generate");
const downloadBtn = document.getElementById("download");
const currencySel = document.getElementById("currency");

function createItemRow(desc = "", qty = 1, price = 0) {
  const row = document.createElement("div");
  row.classList.add("item-row");
  row.innerHTML = `
    <input type="text" placeholder="Description" value="${desc}">
    <input type="number" placeholder="Qty" value="${qty}">
    <input type="number" placeholder="Price" value="${price}">
    <button class="remove">×</button>
  `;
  row.querySelector(".remove").onclick = () => {
    row.remove();
    generatePreview();
  };
  row.querySelectorAll("input").forEach((i) =>
    i.addEventListener("input", generatePreview)
  );
  itemsDiv.appendChild(row);
}

addItemBtn.onclick = () => createItemRow();

function getItems() {
  const rows = document.querySelectorAll(".item-row");
  const items = [];
  rows.forEach((r) => {
    const inputs = r.querySelectorAll("input");
    items.push({
      desc: inputs[0].value,
      qty: parseFloat(inputs[1].value) || 0,
      price: parseFloat(inputs[2].value) || 0,
    });
  });
  return items;
}

function generatePreview() {
  const from = {
    name: document.getElementById("fromName").value,
    address: document.getElementById("fromAddress").value,
    email: document.getElementById("fromEmail").value,
    gstin: document.getElementById("fromGST").value,
  };
  const client = {
    name: document.getElementById("clientName").value,
    address: document.getElementById("clientAddress").value,
    email: document.getElementById("clientEmail").value,
    gstin: document.getElementById("clientGST").value,
  };
  const sgst = parseFloat(document.getElementById("sgst").value) || 0;
  const cgst = parseFloat(document.getElementById("cgst").value) || 0;
  const discount = parseFloat(document.getElementById("discount").value) || 0;
  const currency = currencySel.value;
  const items = getItems();

  let subtotal = 0;
  items.forEach((i) => (subtotal += i.qty * i.price));

  const sgstAmt = (subtotal * sgst) / 100;
  const cgstAmt = (subtotal * cgst) / 100;
  const discountAmt = (subtotal * discount) / 100;
  const total = subtotal + sgstAmt + cgstAmt - discountAmt;

  let itemsHtml = items
    .map(
      (i) => `
      <tr>
        <td>${i.desc}</td>
        <td>${i.qty}</td>
        <td>${currency}${i.price.toFixed(2)}</td>
        <td>${currency}${(i.qty * i.price).toFixed(2)}</td>
      </tr>`
    )
    .join("");

  previewDiv.innerHTML = `
    <div class="invoice-header">
      <h2>Invoice</h2>
      <p>Date: ${new Date().toLocaleDateString()}</p>
    </div>

    <p><strong>From:</strong> ${from.name}<br>${from.address}<br>${from.email}<br><strong>GSTIN:</strong> ${from.gstin || 'N/A'}</p>
    <p><strong>To:</strong> ${client.name}<br>${client.address}<br>${client.email}<br><strong>GSTIN:</strong> ${client.gstin || 'N/A'}</p>

    <table class="invoice-table">
      <tr><th>Description</th><th>Qty</th><th>Price</th><th>Total</th></tr>
      ${itemsHtml}
    </table>

    <div class="totals">
      <p>Subtotal: ${currency}${subtotal.toFixed(2)}</p>
      <p>SGST (${sgst}%): ${currency}${sgstAmt.toFixed(2)}</p>
      <p>CGST (${cgst}%): ${currency}${cgstAmt.toFixed(2)}</p>
      <p>Discount (${discount}%): -${currency}${discountAmt.toFixed(2)}</p>
      <h3>Grand Total: ${currency}${total.toFixed(2)}</h3>
    </div>
  `;
}

generateBtn.onclick = generatePreview;

downloadBtn.onclick = async () => {
  const { jsPDF } = window.jspdf;
  const pdf = new jsPDF("p", "pt", "a4");

  await html2canvas(previewDiv, { scale: 2 }).then((canvas) => {
    const imgData = canvas.toDataURL("image/png");
    const width = pdf.internal.pageSize.getWidth();
    const height = (canvas.height * width) / canvas.width;
    pdf.addImage(imgData, "PNG", 0, 0, width, height);
  });

  pdf.save("invoice.pdf");
};

// Initialize defaults
createItemRow("Web Development Service", 1, 1000);
generatePreview();
currencySel.addEventListener("change", generatePreview);
