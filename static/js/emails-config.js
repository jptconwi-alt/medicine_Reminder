// EmailJS Configuration and Functions

class EmailService {
    constructor() {
        this.initialized = false;
        this.serviceId = "service_rpqhe1i";  // Replace with your EmailJS Service ID
        this.templateId = "template_8l673vr"; // Replace with your EmailJS Template ID
        this.userId = "Gk3_9cXplkZQn8K2Q";        // Replace with your EmailJS User ID
        
        this.init();
    }
    
    async init() {
        try {
            // Initialize EmailJS
            if (typeof emailjs !== 'undefined') {
                await emailjs.init(this.userId);
                this.initialized = true;
                console.log('EmailJS initialized');
            } else {
                console.error('EmailJS SDK not loaded');
            }
        } catch (error) {
            console.error('Failed to initialize EmailJS:', error);
        }
    }
    
    async sendReminder(medicineData) {
        if (!this.initialized) {
            console.error('EmailJS not initialized');
            return false;
        }
        
        const templateParams = {
            to_email: medicineData.userEmail,
            medicine_name: medicineData.name,
            dosage: medicineData.dosage || 'As prescribed',
            time: medicineData.time,
            to_name: medicineData.userEmail.split('@')[0],
            date: new Date().toLocaleDateString(),
            reply_to: 'noreply@medicine-reminder.com'
        };
        
        try {
            const response = await emailjs.send(
                this.serviceId,
                this.templateId,
                templateParams
            );
            
            console.log('Email sent successfully:', response);
            return true;
        } catch (error) {
            console.error('Failed to send email:', error);
            return false;
        }
    }
    
    async sendTestEmail(userEmail) {
        return this.sendReminder({
            userEmail: userEmail,
            name: 'Test Medicine',
            dosage: '1 tablet',
            time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
        });
    }
}

// Create global instance
window.emailService = new EmailService();
