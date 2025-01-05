const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const cheerio = require('cheerio');
const sessions = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const fs = require('fs');
const ejs = require("ejs");
const socketIo = require('socket.io');
const cors = require('cors');

const SSE = require('express-sse'); // Import express-sse


// const rateLimit = require('express-rate-limit');
// const http = require('http');

const http = require('http');
const https = require('https');

const sse = new SSE();
const activeConnections = {}; // To group SSE by `orderId`

app.use(cors());
app.use(express.static(__dirname));
app.set('views', path.join(__dirname)); // Set current directory as the views directory

app.set('view engine', 'ejs');
// Then, you can directly use `/locationIcon.svg` in your templates.


const JWT_SECRET = "m9e3d7i2c6o7m7p2@41502030"; // Replace with a strong secret key
const JWT_EXPIRATION = "7d"; // 7-day session

// Middleware configuration
app.use(cookieParser()); // Using cookie-parser middleware for cookie handling
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// app.set('views', path.join(__dirname, 'views'));

// HTTPS cookie configuration
app.use(
    sessions({
        secret: JWT_SECRET,  // Change to a strong secret key
        resave: false,
        saveUninitialized: true,
        cookie: {
            httpOnly: true,  // Makes the cookie accessible only by the server
            secure: true,    // Ensures cookie is only sent over HTTPS
            sameSite: 'Strict',  // Prevents cross-site request forgery (CSRF)
            maxAge: 7 * 24 * 60 * 60 * 1000  // Cookie expiration (1 week)
        }
    })
);

// MongoDB connection configuration
const uri = "mongodb+srv://krishil:hwMRi.iXePK.4J3@medicompuser.vjqrgbt.mongodb.net";
const options = {
    useUnifiedTopology: true,
    maxPoolSize: 10,
    socketTimeoutMS: 45000,
    connectTimeoutMS: 30000,
};

const client = new MongoClient(uri, options);

// Connect to MongoDB
async function connectToDb() {
    try {
        await client.connect();
        console.log('Connected to MongoDB with connection pooling enabled!');
    } catch (err) {
        console.error('Error connecting to MongoDB:', err);
    }
}

connectToDb();

// Authentication middleware to validate JWT token
const unauthenticatedRoutes = ['/manifest.json'];

const authenticateToken = (req, res, next) => {
    if (unauthenticatedRoutes.includes(req.path)) {
        return next(); // Bypass authentication
    }
    // console.log('Request path:', req.path);
    // console.log('Request headers:', req.headers);
    // console.log('Request cookies:', req.cookies);

    const token = req.cookies.token || req.headers['authorization'];
    if (!token) {
        req.isAuthenticated = false;
        console.error('No token provided.');
        return res.redirect('/landingPage.html');
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            req.isAuthenticated = false;
            console.error('JWT verification failed:', err.message);
            return res.status(403).json({ success: false, message: "Invalid token" });
        }

        req.isAuthenticated = true;

        req.userId = decoded.userId;
        next();
    });
};


// const serverOptions = {
//     cert: fs.readFileSync('/etc/letsencrypt/live/openpills.com/fullchain.pem'),
//     key: fs.readFileSync('/etc/letsencrypt/live/openpills.com/privkey.pem')
// };

// // Create HTTPS server with SSL certificates
// const server = https.createServer(serverOptions, app);


const server = http.createServer();
const io = socketIo(server);

const db = client.db('MedicompDb');

io.on('connection', (socket) => {
    console.log('A chemist connected via WebSocket.');

    // Chemist registration event
    socket.on('registerChemist', async (chemistDetails) => {
        console.log(chemistDetails)
        const { name, address, phone, authToken, chemistId } = chemistDetails;

        if (!chemistId) {
            console.log('Invalid registration attempt: No chemistId provided.');
            return;
        }

        try {
            // Save chemist details and socket information in MongoDB
            const chemistsCollection = db.collection('LocalChemists');
            await chemistsCollection.updateOne(
                { chemistId },
                {
                    $set: {
                        name,
                        address,
                        phone,
                        authToken, // Store the unique token
                        socketID: socket.id,
                        registeredAt: new Date(),
                    },
                },
                { upsert: true }
            );

            console.log(`Medicomp Server: Chemist ${chemistId} registered with socket ${socket.id}.`);
        } catch (err) {
            console.error('Error saving chemist data to MongoDB:', err);
        }




        // Handle disconnection
        socket.on('disconnect', async () => {
            console.log(`Chemist ${chemistId} disconnected.`);
            try {
                // Remove socketID on disconnect
                const chemistsCollection = db.collection('LocalChemists');
                await chemistsCollection.updateOne(
                    { chemistId },
                    { $unset: { socketID: '' } }
                );
            } catch (err) {
                console.error('Error clearing socket info in MongoDB:', err);
            }
        });

        socket.on('PrescriptionOk', async (orderId) => {
            console.log("ALL OK " + orderId)
            const ordersCollection = db.collection('Orders');
            await ordersCollection.updateOne(
                { orderId }, // Find the document with matching orderId
                { $set: { PrescriptionVerified: 'Done' } } // Update PrescriptionVerified to 'Done'
            );

            // alert(`Your order was rejected: ${message.reason}`);
            // Update the UI, show an option to upload a new prescription
        });

        socket.on('updateOrderStatusFromChemist', async (data) => {
            const status = data.status;

            const orderId = data.orderId;


            console.log("Order Status Updated For " + orderId)

            const ordersCollection = db.collection('Orders');
            await ordersCollection.updateOne(
                { orderId }, // Find the document with matching orderId
                { $set: { status: status } } // Update PrescriptionVerified to 'Done'
            );


            const update = {
                orderId,
                status,
                timestamp: new Date().toISOString(),
            };

            console.log('Current activeConnections:', activeConnections);


            if (activeConnections[orderId]) {
                activeConnections[orderId].forEach((clientRes) => {
                    clientRes.write(`data: ${JSON.stringify(update)}\n\n`);
                });
            } else {
                console.log(`No active connections for Order ${orderId}`);
            }


        });

        socket.on('orderRejection', async (message) => {
            const ordersCollection = db.collection('Orders');
            await ordersCollection.updateOne(
                { orderId }, // Find the document with matching orderId
                { $set: { PrescriptionVerified: 'Wrong' } } // Update PrescriptionVerified to 'Done'
            );

        });



    });
});




// Start the Medicomp server
server.listen(8080, () => {
    console.log('OpenPills Server is running on http://localhost:8080');
});



app.get('/landing', authenticateToken, async (req, res) => {
    try {
        // Check if the user is authenticated
        if (req.isAuthenticated) {
            // Redirect to /home if authenticated
            return res.redirect('/home');
        }

        // Otherwise, serve the landing page
        res.sendFile(__dirname + "/landingPage.html");
    } catch (error) {
        console.error('Error in landing page route:', error);
        res.status(500).send('An error occurred.');
    }
});


app.get('/login', async (req, res) => {
    await res.sendFile(__dirname + "/registrationPage.html");
})

// Redirect '/' to '/home' with authentication
app.get('/', authenticateToken, async (req, res) => {
    // console.log('Root endpoint reached');
    await res.sendFile(__dirname + "/home.html");
});

// Authenticate and serve the main page at '/home'
app.get('/home', authenticateToken, async (req, res) => {
    await res.sendFile(__dirname + "/home.html");
});


app.get('/locationIcon.svg', authenticateToken, async (req, res) => {
    await res.sendFile(__dirname + "/locationIcon.svg");
})

// Route to fetch medicine name data
app.get('/medicineName', authenticateToken, async (req, res) => {
    const db = client.db("MedicompDb");
    const collection = db.collection("biggerDOM");

    const userCartCollection = db.collection("User");

    const userId = new ObjectId(req.userId);

    const user = await userCartCollection.findOne({ _id: userId });

    var userCart = [];
    // console.log(user.cartItems[0].productId)
    // console.log(await collectionForMedicineDetails.findOne({ _id: user.cartItems[0].productId }))
    for (var items = 0; items < user.cartItems.length; items++) {
        var tempId = new ObjectId(user.cartItems[items].productId);
        var taemp = await collection.findOne({ _id: tempId });

        var tempItem = {};
        tempItem._id = taemp._id;
        tempItem.quantity = user.cartItems[items].quantity;

        // Push the modified item into the userCart array
        userCart.push(tempItem);
    }
    // console.log(userCart)

    try {
        const records = await collection.aggregate([
            {
                $search: {
                    index: "searchFromBiggerDOM",
                    compound: {
                        should: [
                            {
                                regex: {
                                    query: req.query['q'].replace(/&/g, '\\&'),
                                    path: "medicineName",
                                    allowAnalyzedField: true
                                }
                            },
                            {
                                autocomplete: {
                                    query: req.query['q'],
                                    path: "medicineName",
                                }
                            },
                            {
                                autocomplete: {
                                    query: req.query['q'],
                                    path: "packSize",
                                }
                            },
                        ]
                    }
                }
            },
            { $limit: 10 }
        ]).toArray();

        if (records.length > 0) {


            for (var i = 0; i < userCart.length; i++) {

                for (var j = 0; j < records.length; j++) {
                    // console.log(records[j]._id.toString())

                    if (records[j]._id.toString()==userCart[i]._id.toString()){
                        records[j].exists=true;
                        records[j].quantity=userCart[i].quantity;
                    }
                    }
            }


            res.send(records);
        } else {
            const recordsFallback = await collection.aggregate([
                {
                    $search: {
                        index: "searchFromBiggerDOM",
                        compound: {
                            should: [
                                {
                                    regex: {
                                        query: req.query['q'].replace(/&/g, '\\&'),
                                        path: "medicineName",
                                        allowAnalyzedField: true
                                    }
                                },
                                {
                                    autocomplete: {
                                        query: req.query['q'],
                                        path: "medicineName",
                                        fuzzy: {
                                            maxEdits: 2,
                                            prefixLength: 1
                                        }
                                    }
                                },
                                {
                                    autocomplete: {
                                        query: req.query['q'],
                                        path: "packSize",
                                        fuzzy: {
                                            maxEdits: 2,
                                            prefixLength: 1
                                        }
                                    }
                                },
                            ]
                        }
                    }
                },
                { $limit: 10 }
            ]).toArray();


            for (var i = 0; i < userCart.length; i++) {

                for (var j = 0; j < recordsFallback.length; j++) {
                    // console.log(records[j]._id.toString())

                    if (recordsFallback[j]._id.toString()==userCart[i]._id.toString()){
                        recordsFallback[j].exists=true;
                        recordsFallback[j].quantity=userCart[i].quantity;
                    }
                    }
            }

            res.send(recordsFallback);
        }

    } catch (err) {
        console.error('Error inserting medicine', err);
    }
});

// Login endpoint
app.post("/login", async (req, res) => {
    const { phone, name } = req.body;

    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("User");

        let user = await collection.findOne({ phone });

        if (!user) {
            const newUser = {
                name: name || "Unknown User",
                phone,
                cartItems: [],
                createdAt: new Date(),
                updatedAt: new Date(),
            };
            const result = await collection.insertOne(newUser);
            user = result.ops[0];
        }

        const token = jwt.sign(
            { userId: user._id, phone: user.phone },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        // Set token as a cookie
        res.cookie('token', token, {
            httpOnly: true,        // Ensures cookie can't be accessed by JavaScript
            secure: process.env.NODE_ENV === 'production',  // Use 'secure' in production (requires HTTPS)
            maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days in milliseconds
            sameSite: 'Strict',    // Prevents the cookie from being sent in cross-site requests
        });

        // Send success response
        res.json({ success: true, message: "Login successful!" });

    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ success: false, message: "Server error!" });
    }
});

app.get("/cart-items", authenticateToken, async (req, res) => {
    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("User");

        const collectionForMedicineDetails = db.collection("biggerDOM");

        // Fetch user by the ID stored in the token
        const userId = new ObjectId(req.userId);

        const user = await collection.findOne({ _id: userId });

        var userCart = [];
        // console.log(user.cartItems[0].productId)
        // console.log(await collectionForMedicineDetails.findOne({ _id: user.cartItems[0].productId }))
        for (var items = 0; items < user.cartItems.length; items++) {
            var tempId = new ObjectId(user.cartItems[items].productId);
            var tempItem = await collectionForMedicineDetails.findOne({ _id: tempId });

            // Add quantity to the item
            tempItem.quantity = user.cartItems[items].quantity;

            // Push the modified item into the userCart array
            userCart.push(tempItem);
        }


        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Send the cart items of the logged-in user
        res.json({
            success: true,
            cartItems: userCart,
        });

    } catch (error) {
        console.error("Error fetching cart:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get("/cart", authenticateToken, async (req, res) => {


    await res.sendFile(__dirname + "/cart.html");

});

app.get("/comparison", authenticateToken, async (req, res) => {


    await res.sendFile(__dirname + "/comparisonPage.html");

});


app.get("/comparisonRepeatOrder/:orderId", authenticateToken, async (req, res) => {
    const { orderId } = req.params;

    const finalData = { orderId: orderId }; // Example data


    res.render(__dirname + '/comparisonPageRepeatOrder.ejs', {
            final:finalData// Convert object to string
        });    // await res.sendFile(__dirname + "/finalcheckoutpage.html");

});



app.post("/checkout", authenticateToken, async (req, res) => {


    console.log(req.body)

    if(typeof(req.body.medicineNames)=='string'){
        req.body.medicineNames=[req.body.medicineNames];
    }
    if(typeof(req.body.qty)=='string'){
        req.body.qty=[req.body.qty];
    }
    if(typeof(req.body.medicinePrices)=='string'){
        req.body.medicinePrices=[req.body.medicinePrices];
    }
    if(typeof(req.body.medicinePackSize)=='string'){
        req.body.medicinePackSize=[req.body.medicinePackSize];
    }
    if(typeof(req.body.medicineId)=='string'){
        req.body.medicineId=[req.body.medicineId];
    }
    const db = client.db("MedicompDb");
    const collection = db.collection("User");

    // Fetch user by the ID stored in the token
    // const userId = new ObjectId(req.userId);
    // const user = await collection.findOne({ _id: userId });

    // console.log(user)
    console.log("User Id -> " + req.userId)



    res.render(__dirname + '/finalCheckoutPage.ejs', {
        final: JSON.stringify(req.body, null, 2) // Convert object to string
    });    // await res.sendFile(__dirname + "/finalcheckoutpage.html");

});


app.post("/compareCartItems", authenticateToken, async (req, res) => {

    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("User");

        const collectionForMedicineDetails = db.collection("biggerDOM");

        // Fetch user by the ID stored in the token
        const userId = new ObjectId(req.userId);

        const user = await collection.findOne({ _id: userId });

        var userCart = [];
        // console.log(user.cartItems[0].productId)
        // console.log(await collectionForMedicineDetails.findOne({ _id: user.cartItems[0].productId }))
        for (var items = 0; items < user.cartItems.length; items++) {
            var tempId = new ObjectId(user.cartItems[items].productId);
            var tempItem = await collectionForMedicineDetails.findOne({ _id: tempId });

            // Add quantity to the item
            tempItem.medicineId = tempId;
            tempItem.quantity = user.cartItems[items].quantity;

            // Push the modified item into the userCart array
            userCart.push(tempItem);
        }

      

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }


        // const chemistIds = ["chemist123-token"]; // Example IDs
        const chemistsCollection = db.collection('LocalChemists');

        const chemistIds = await chemistsCollection.distinct('chemistId');


        // Function to fetch data for a single chemist
        const fetchDataFromChemist = async (chemistId) => {
            const chemist = await chemistsCollection.findOne({ chemistId });

            if (!chemist) {
                console.log(`Unauthorized or unknown chemist: ${chemistId}`);
                return { chemistId, error: "Unauthorized or unknown chemist" };
            }

            const chemistSocket = io.sockets.sockets.get(chemist.socketID);

            if (!chemistSocket) {
                console.log(`Chemist ${chemistId} socket not found.`);
                return { chemistId, error: "Chemist socket not found" };
            }

            var chemistName=chemist.chemistName;
            // Emit fetchData event and wait for response
            console.log(userCart)
            return new Promise((resolve, reject) => {
                chemistSocket.emit("fetchData", { authToken: chemist.authToken, userCart }, (response) => {
                    if (response) {
                        console.log(`Data received from Chemist ${chemistId}:`, response);
                        resolve({ chemistId,chemistName, data: response }); // Return response with chemistId
                    } else {
                        reject(new Error(`No response from chemist ${chemistId}.`));
                    }
                });
            });
        };

        // Use Promise.all to fetch data from all chemists in parallel
        const chemistResponses = await Promise.all(
            chemistIds.map((chemistId) =>
                fetchDataFromChemist(chemistId).catch((error) => ({
                    chemistId,
                    error: error.message,
                }))
            )
        );

        console.log("Response form chemsit")
        // Send combined response to the user
        res.json({
            success: true,
            responses: chemistResponses, // Array of responses from each chemist
        });

        // res.render('comparisonPage', { data: responseData||[] });


    } catch (err) {
        console.error('Error requesting data from chemist:', err);
        return res.status(500).json({ error: 'Failed to request data from chemist.' });
    }


});






const multer = require('multer');
const upload = multer(); // Memory storage if you want to store the file temporarily in memory

app.post('/placeOrder', authenticateToken, upload.single('prescription'), async (req, res) => {
    console.log(req.body)
    console.log(req.file)
    const { medicineList, chemistId,medicineQty,medicineId } = req.body;
    console.log(medicineQty)
    const db = client.db("MedicompDb");
    const chemistsCollection = db.collection('LocalChemists');
    const collection = db.collection("User");

    const chemist = await chemistsCollection.findOne({ chemistId });
    
    
    
    var realtimeCartData = {};
    
    console.log('Place Order endpoint hit');
    
    // const { customerName, phoneNumber, address, medicineList, chemistId, authToken } = req.body;
    const userId = req.userId;
    const user = await collection.findOne({ _id: new ObjectId(userId) });
    console.log(user)
    console.log(user.cartIems)
    var customerName = user.name;
    var phoneNumber = user.phone;

    const selectedAddress = user.savedAddresses.find(address => address.selected);

        if (!selectedAddress) {
            return res.status(404).json({ success: false, message: "No selected address found!" });
        }


    var address = selectedAddress;
    var prescription = req.file;

    prescription = prescription ? prescription : "Not Required";

    console.log("Prescription : " + prescription)

    // Validate the incoming data
    if (!customerName || !phoneNumber || !address || !medicineList || !chemistId) {
        console.log('Missing required fields');
        return res.status(400).json({ error: 'All fields are required.' });
    }

    console.log('Order details received:', req.body); // Log the received data
    try {
        // Store the order in MongoDB
        const ordersCollection = db.collection('Orders');
        const count = await ordersCollection.countDocuments();


        const orderId = `Order_${count}`;

        realtimeCartData.orderId = orderId;

        
        const newOrder = {
            orderId: `Order_${count}`,
            customerId:req.userId,
            customerName,
            phoneNumber,
            address: address.fullAddress,
            lat: address.lat,
            lng: address.lng,
            medicineList,
            medicineId:medicineId,
            medicineQty,
            prescription: prescription, // You can save the binary data here or a link to the file
            chemistId,
            status: 'Pending', // Initial status
            createdAt: new Date(),
            PrescriptionVerified: (prescription == "Not Required" ? "Done" : "Pending"),
        };
        
        if(typeof(newOrder.medicineList)=="string"){
            newOrder.medicineList=[newOrder.medicineList];
        }
        if(typeof(newOrder.medicineQty)=="string"){
            newOrder.medicineQty=[newOrder.medicineQty];
        }
        if(typeof(newOrder.medicinePrices)=="string"){
            newOrder.medicinePrices=[newOrder.medicinePrices];
        }
        if(typeof(newOrder.medicinePackSize)=="string"){
            newOrder.medicinePackSize=[newOrder.medicinePackSize];
        }
        if(typeof(newOrder.medicineId)=="string"){
            newOrder.medicineId=[newOrder.medicineId];
        }

        // Emit the order data to the chemist via WebSocket
        const chemistsCollection = db.collection('LocalChemists');
        const chemist = await chemistsCollection.findOne({ chemistId });

        const chemistSocketForOrders = io.sockets.sockets.get(chemist.socketID);
        if (chemistSocketForOrders) {
            chemistSocketForOrders.emit('newOrder', newOrder);
            console.log(`Order ${orderId} sent to Chemist ${chemistId}`);
            console.log(newOrder)
            // res.status(200).json({ message: 'Order placed successfully', orderId });
        } else {
            console.log(`No active socket for Chemist ${chemistId}`);
            // res.status(404).json({ error: 'Chemist not available' });
        }



        if (chemistSocketForOrders) {

            const result = await ordersCollection.insertOne({
                _id: `Order_${count}`,
                orderId: `Order_${count}`,
                customerId:req.userId,
                customerName,
                phoneNumber,
                address: address.fullAddress,
                lat: address.lat,
                lng: address.lng,
                medicineList,
                medicineId:medicineId,
                medicineQty,
                prescription,
                chemistId,
                customerToken: req.userId,
                status: 'Pending', // Initial status
                createdAt: new Date(),
                PrescriptionVerified: (prescription == "Not Required" ? "Done" : "Pending"),

            });
            console.log('Order inserted into MongoDB:', result); // Log successful DB insert

        }

        // console.log(realtimeCartData)

        // await res.render(__dirname+'/orderPlaced.ejs', {
        //     final: JSON.stringify(realtimeCartData, null, 2) // Convert object to string
        // });

        res.redirect(`/order-status-page?orderId=${orderId}`);






    } catch (err) {
        console.error('Error placing order:', err);
        console.log(err.code)
        // res.status(500).json({ error: 'Failed to place order.' });
    }
});

// SSE route with authentication
// SSE route with authentication
app.get("/order-status-page", authenticateToken, async (req, res) => {
    const orderId = req.query.orderId; // Get orderId from query parameters
    const userId = req.userId;

    // const user = await collection.findOne({ _id: userId });

    if (!orderId) {
        return res.status(400).send("Order ID is required");
    }
    // Example order data (replace this with your database query logic)

    const db = client.db("MedicompDb");
    const ordersCollection = db.collection('Orders');

    // Ensure the user has access to this order
    const userOk = await ordersCollection.findOne({ customerToken: userId });
    const orderOk = await ordersCollection.findOne({ orderId: orderId });

    if (!orderOk || !userOk) {
        return res.status(403).send("You are not authorized to access this order.");
    }

    if(typeof(orderOk.medicineList)=="string"){
        orderOk.medicineList=[orderOk.medicineList];
    }
    if(typeof(orderOk.medicineQty)=="string"){
        orderOk.medicineQty=[orderOk.medicineQty];
    }

    res.render(__dirname + '/orderStatusPage2.ejs', {
        final: JSON.stringify(orderOk, null, 2),
        orderId: orderId
    });

});


app.get("/getTotalCartItems", authenticateToken, async (req, res) => {
    try {
        const userId = req.userId;  // Assuming the userId is extracted from the token

        // Find the user by their ID
        const db = client.db("MedicompDb");
        const collection = db.collection("User");

        const user = await collection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Count the number of distinct items in the cart (no need to consider quantity)
        const distinctItemsCount = user.cartItems ? user.cartItems.length : 0;

        // Return the distinct item count
        res.json({
            success: true,
            totalItems: distinctItemsCount
        });

    } catch (error) {
        console.error("Error fetching total cart items:", error);
        res.status(500).json({ success: false, message: "Server error!" });
    }
});


app.get("/order-updates", authenticateToken, async (req, res) => {
    const orderId = req.query.orderId;
    const userId = req.userId;

    if (!orderId) {
        return res.status(400).send("Order ID is required");
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.status(200); // Ensure the client sees 200 OK immediately.


    // Write a ping to keep the connection alive
    res.write(': ping\n\n');

    // Save the response object for this orderId
    if (!activeConnections[orderId]) {
        activeConnections[orderId] = [];
    }
    activeConnections[orderId].push(res);

    console.log(`Client connected for Order ${orderId}`);

    // Handle client disconnect
    req.on('close', () => {
        console.log(`Client disconnected for Order ${orderId}`);
        activeConnections[orderId] = activeConnections[orderId].filter((clientRes) => clientRes !== res);
    });



});




app.post("/addItemToCart", authenticateToken, async (req, res) => {
    console.log("Sa")
    const { productId } = req.body; // Assuming phone is provided to identify the user
    if (!productId) {
        return res.status(400).json({ success: false, message: "Product ID is required!" });
    }

    try {
        // Find the user by phone (you can also use _id if needed)
        const db = client.db("MedicompDb");
        const collection = db.collection("User");

        const userId = new ObjectId(req.userId);


        const user = await collection.findOne({ _id: userId });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Check if the product is already in the user's cart
        // console.log(productId)
        const existingItem = user.cartItems.find(item => item.productId.toString() === productId);

        // console.log(existingItem)
        if (existingItem) {
            // If product exists, just increment the quantity
            await collection.updateOne(
                { userId, "cartItems.productId": existingItem.productId },
                { $inc: { "cartItems.$.quantity": 1 } }
            );
            res.json({ success: true, message: "Product quantity updated!" });
        } else {
            // If product is not in the cart, add it with quantity 1
            await collection.updateOne(
                { _id: userId },
                { $push: { cartItems: { productId, quantity: 1 } } }
            );
            res.json({ success: true, message: "Product added to cart!" });
        }
    } catch (error) {
        console.error("Error adding item to cart:", error);
        res.status(500).json({ success: false, message: "Server error!" });
    }
});

app.post("/removeItemFromCart", authenticateToken, async (req, res) => {
    const { productId } = req.body; // The product ID to remove from the cart
    if (!productId) {
        return res.status(400).json({ success: false, message: "Product ID is required!" });
    }

    try {
        // Find the user by userId (passed through authenticateToken middleware)
        const db = client.db("MedicompDb");
        const collection = db.collection("User");

        const userId = new ObjectId(req.userId);

        const user = await collection.findOne({ _id: userId });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Check if the product exists in the user's cart
        const existingItem = user.cartItems.find(item => item.productId === productId);

        if (!existingItem) {
            return res.status(404).json({ success: false, message: "Product not found in cart!" });
        }

        // Remove the item from the cart using the $pull operator
        await collection.updateOne(
            { _id: userId },
            { $pull: { cartItems: { productId: productId } } }
        );

        res.json({ success: true, message: "Product removed from cart!" });
    } catch (error) {
        console.error("Error removing item from cart:", error);
        res.status(500).json({ success: false, message: "Server error!" });
    }
});

app.post("/updateCartItem", authenticateToken, async (req, res) => {
    const { cartItemId, qty } = req.body; // Extract cartItemId and qty from the request body

    if (!cartItemId || qty === undefined) {
        return res.status(400).json({ success: false, message: "cartItemId and qty are required!" });
    }

    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("User");

        const userId = req.userId; // Assuming the user ID is extracted from the token

        // Find the user by userId
        const user = await collection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Find the index of the item in the user's cart based on cartItemId (productId)
        const cartItemIndex = user.cartItems.findIndex(item => item.productId === cartItemId);

        if (cartItemIndex === -1) {
            return res.status(404).json({ success: false, message: "Item not found in the cart!" });
        }

        // Update the quantity of the found cart item
        user.cartItems[cartItemIndex].quantity = qty;

        // Save the updated cart back to the database
        await collection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { cartItems: user.cartItems } }
        );

        res.json({ success: true, message: "Cart item quantity updated successfully!" });
    } catch (error) {
        console.error("Error updating cart item:", error);
        res.status(500).json({ success: false, message: "Server error!" });
    }
});


app.get('/getUserAddresses',authenticateToken, async (req, res) => {
    const db = client.db("MedicompDb");
    const collection = db.collection("User");

    const userId = req.userId; // Assuming the user ID is extracted from the token

    // Find the user by userId
    const user = await collection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
        return res.status(404).json({ success: false, message: "User not found!" });
    }

    // res.send(user.savedAddresses)
    res.json({ success: true, message: user.savedAddresses });
})

app.get('/getCurrentSelectedAddress', authenticateToken, async (req, res) => {
    const db = client.db("MedicompDb");
    const collection = db.collection("User");

    const userId = req.userId; // Assuming the user ID is extracted from the token

    try {
        // Find the user by userId
        const user = await collection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Find the address with selected: true
        const selectedAddress = user.savedAddresses.find(address => address.selected);

        if (!selectedAddress) {
            return res.status(404).json({ success: false, message: "No selected address found!" });
        }

        // Return the selected address
        res.json({ success: true, message: selectedAddress });
    } catch (error) {
        console.error("Error fetching selected address:", error);
        res.status(500).json({ success: false, message: "Internal server error!" });
    }
});


app.post('/updateSelectedAddress', authenticateToken, async (req, res) => {
    const db = client.db("MedicompDb");
    const collection = db.collection("User");

    const userId = req.userId; // Extracted from the token
    const { addressId } = req.body; // `addressId` sent in the request body

    try {
        // Find the user by userId
        const user = await collection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Update savedAddresses to set all `selected` fields to false
        user.savedAddresses.forEach(address => {
            address.selected = false;
        });

        // Find the address with the given addressId and set its `selected` to true
        const updatedAddress = user.savedAddresses.find(address => address.address_id === addressId);
        if (updatedAddress) {
            updatedAddress.selected = true;
        } else {
            return res.status(404).json({ success: false, message: "Address ID not found!" });
        }

        // Update the user's savedAddresses in the database
        await collection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { savedAddresses: user.savedAddresses } }
        );

        res.json({ success: true, message: "Address selection updated successfully!", updatedAddress });
    } catch (error) {
        console.error("Error updating selected address:", error);
        res.status(500).json({ success: false, message: "Internal server error!" });
    }
});

app.post('/saveNewAddress', authenticateToken, async (req, res) => {
    const db = client.db("MedicompDb");
    const collection = db.collection("User");

    
    const userId = req.userId; // Assuming the user ID is extracted from the token
    const { category, fullAddress, lat, lng } = req.body;
    console.log(req.body)

    // Validation
    if (!category || !fullAddress || !lat || !lng) {
        return res.status(400).json({ success: false, message: "All fields are required!" });
    }

    try {
        // Find the user by userId
        const user = await collection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Get the list of saved addresses
        const savedAddresses = user.savedAddresses || [];
        
        // Get the last address_id and increment it
        let newAddressId = "userAddress_001";
        if (savedAddresses.length > 0) {
            const lastAddress = savedAddresses[savedAddresses.length - 1];
            const lastId = lastAddress.address_id;
            const lastIndex = parseInt(lastId.split('_')[1]);
            newAddressId = `userAddress_${String(lastIndex + 1).padStart(3, '0')}`;
        }

        user.savedAddresses.forEach(address => {
            address.selected = false;
        });

        await collection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { "savedAddresses.$[].selected": false } } // Set `selected` to false for all addresses
        );

        // Create the new address object
        const newAddress = {
            category,
            fullAddress,
            lat,
            lng,
            address_id: newAddressId,
            selected: true // New addresses are not selected by default
        };

        // Update the user's savedAddresses array
        const result = await collection.updateOne(
            { _id: new ObjectId(userId) },
            { $push: { savedAddresses: newAddress } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ success: false, message: "Failed to save address!" });
        }

        res.status(201).json({ success: true, message: "Address saved successfully!", address: newAddress });
    } catch (error) {
        console.error("Error saving address:", error);
        res.status(500).json({ success: false, message: "Internal server error!" });
    }
});


app.get('/getCurrentOrders', authenticateToken, async (req, res) => {
    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("Orders");
        
        const customerToken = req.userId; // Assuming customerToken is stored in the token as `userId`

        // Fetch orders matching customerToken and status 'Pending'
        const orders = await collection.find({ 
            customerToken, 
            status: { $in: ["Pending", "Out For Delivery"] } // Matches either status
        }).toArray();
        

        if (!orders || orders.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'No pending orders found for this user.' 
            });
        }

        
        res.json({ success: true, orders });

    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while fetching orders.'
        });
    }
});
app.get('/getCancelledOrders', authenticateToken, async (req, res) => {
    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("Orders");
        
        const customerToken = req.userId; // Assuming customerToken is stored in the token as `userId`

        // Fetch orders matching customerToken and status 'Pending'
        const orders = await collection.find({ 
            customerToken, 
            status: "Cancelled" 
        }).toArray();

        if (!orders || orders.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'No pending orders found for this user.' 
            });
        }

        // Render EJS page with filtered orders
        res.json({ success: true, orders });

    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while fetching orders.'
        });
    }
});
app.get('/getCompletedOrders', authenticateToken, async (req, res) => {
    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("Orders");
        
        const customerToken = req.userId; // Assuming customerToken is stored in the token as `userId`

        // Fetch orders matching customerToken and status 'Pending'
        const orders = await collection.find({ 
            customerToken, 
            status: "Completed" 
        }).toArray();

        if (!orders || orders.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'No pending orders found for this user.' 
            });
        }

        // Render EJS page with filtered orders
        res.json({ success: true, orders });

    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while fetching orders.'
        });
    }
});


app.get('/prescription/:orderId',authenticateToken, async (req, res) => {
    const { orderId } = req.params;
    const user=req.userId;


    if (!user) {
        return res.status(404).json({ success: false, message: "User not found!" });
    }

    try {
        const db = client.db("MedicompDb");
        const collection = db.collection("Orders");

        // Find the order by orderId
        const order = await collection.findOne({ orderId });
        if (!order || !order.prescription || !order.prescription.buffer ) {
            return res.status(404).send("Prescription not found.");
        }

        // Set the content type to match the image's MIME type
        res.contentType(order.prescription.mimetype);
        res.send(order.prescription.buffer.buffer); // Send the binary image buffer
    } catch (error) {
        console.error("Error fetching prescription:", error);
        res.status(500).send("Error fetching prescription.");
    }
});



app.get("/compareCartItemsFromRepeatOrder/:orderId", authenticateToken, async (req, res) => {

    const db = client.db("MedicompDb");
    const collection = db.collection("User");

    const collectionForMedicineDetails = db.collection("biggerDOM");
    const collectionForOrders = db.collection("Orders");

    const { orderId } = req.params;
    console.log(orderId)
    
    const order = await collectionForOrders.findOne({ orderId: orderId });

    console.log(order)
    try {

        var medicineId=order.medicineId;
        var quantity=order.medicineQty;
        var medicineName=order.medicineList;


        // Fetch user by the ID stored in the token
        const userId = new ObjectId(req.userId);

        const user = await collection.findOne({ _id: userId });

        if(typeof(medicineId)=="string"){
            medicineId=[medicineId];
        }
        if(typeof(quantity)=="string"){
            quantity=[quantity];
        }
        if(typeof(medicineName)=="string"){
            medicineName=[medicineName];
        }

        console.log(quantity)

        var userCart=[];
        // console.log(user.cartItems[0].productId)
        // console.log(await collectionForMedicineDetails.findOne({ _id: user.cartItems[0].productId }))
        for (var items = 0; items < medicineName.length; items++) {
            var tempId = new ObjectId(medicineId[items]);
            var tempItem = await collectionForMedicineDetails.findOne({ _id: tempId });

            // Add quantity to the item
            tempItem.quantity = quantity[items];

            // Push the modified item into the userCart array
            userCart.push(tempItem);
        }


        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }


        // const chemistIds = ["chemist123-token"]; // Example IDs
        const chemistsCollection = db.collection('LocalChemists');

        const chemistIds = await chemistsCollection.distinct('chemistId');


        // Function to fetch data for a single chemist
        const fetchDataFromChemist = async (chemistId) => {
            const chemist = await chemistsCollection.findOne({ chemistId });

            if (!chemist) {
                console.log(`Unauthorized or unknown chemist: ${chemistId}`);
                return { chemistId, error: "Unauthorized or unknown chemist" };
            }

            const chemistSocket = io.sockets.sockets.get(chemist.socketID);

            if (!chemistSocket) {
                console.log(`Chemist ${chemistId} socket not found.`);
                return { chemistId, error: "Chemist socket not found" };
            }

            var chemistName=chemist.chemistName;
            // Emit fetchData event and wait for response
            console.log(userCart)
            return new Promise((resolve, reject) => {
                chemistSocket.emit("fetchData", { authToken: chemist.authToken, userCart }, (response) => {
                    if (response) {
                        console.log(`Data received from Chemist ${chemistId}:`, response);
                        resolve({ chemistId,chemistName, data: response }); // Return response with chemistId
                    } else {
                        reject(new Error(`No response from chemist ${chemistId}.`));
                    }
                });
            });
        };

        // Use Promise.all to fetch data from all chemists in parallel
        const chemistResponses = await Promise.all(
            chemistIds.map((chemistId) =>
                fetchDataFromChemist(chemistId).catch((error) => ({
                    chemistId,
                    error: error.message,
                }))
            )
        );

        // Send combined response to the user
        res.json({
            success: true,
            responses: chemistResponses, // Array of responses from each chemist
        });

        // res.render('comparisonPage', { data: responseData||[] });


    } catch (err) {
        console.error('Error requesting data from chemist:', err);
        return res.status(500).json({ error: 'Failed to request data from chemist.' });
    }


});


app.get('/fetchById/:id', authenticateToken, async (req, res) => {
    try {
        const db = client.db('MedicompDb');
        const collection = db.collection('biggerDOM');
        const usersCartCollection = db.collection('User');
        
        const { id } = req.params;
        const userId = req.userId; // Assuming user ID is available from authentication middleware

        // Validate and convert _id to ObjectId
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ success: false, message: 'Invalid ID format' });
        }

        // Fetch medicine data
        const medicineData = await collection.findOne({ _id: new ObjectId(id) });

        if (!medicineData) {
            return res.status(404).send('Medicine not found');
        }

        // Check if the product exists in the user's cart
        const userCart = await usersCartCollection.findOne({ _id: new ObjectId(userId) });

        if (userCart && userCart.cartItems) {
            const cartItem = userCart.cartItems.find(item => item.productId === id);

            if (cartItem) {
                medicineData.exists = true;
                medicineData.quantity = cartItem.quantity; // Add quantity if exists
            } else {
                medicineData.exists = false;
            }
        } else {
            medicineData.exists = false;
        }

        console.log(medicineData)
        // Render the EJS page with the updated data
        res.render(__dirname + '/singleMedicinePage.ejs', {
            final: medicineData
        });
    } catch (error) {
        console.error('Error fetching document:', error);
        res.status(500).json({ success: false, message: 'An error occurred while fetching the document.' });
    }
});




// Port configuration
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`This app is listening on port ${port}`));
