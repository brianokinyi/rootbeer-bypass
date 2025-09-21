Java.perform(function() {
    // Get references to necessary Java classes
    var Toast = Java.use("android.widget.Toast");
    var ActivityThread = Java.use("android.app.ActivityThread");
    var String = Java.use("java.lang.String"); // For creating Java String objects

    // Get the application context
    var currentApplication = ActivityThread.currentApplication();
    var context = currentApplication.getApplicationContext();
    console.log("Context: " + context);

    // Schedule the Toast creation and display on the main UI thread
    Java.scheduleOnMainThread(function() {
        try {
            // Create a Java String for the Toast message
            var toastMessage = String.$new("Hello Guru! This app can be injected with custom scripts!"); 

            // Create and show the Toast
            Toast.makeText(context, toastMessage, Toast.LENGTH_SHORT.value).show();
            console.log("Toast displayed successfully.");
        } catch (error) {
            console.error("Error displaying Toast: " + error);
        }
    });
});
