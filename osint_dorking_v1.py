#OSINT Dorking v1
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import webbrowser
import urllib.parse
from datetime import datetime

class OSINTDorkingTool:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Dorking Tool v1.0")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')
        
        # Search engines configuration
        self.search_engines = {
            'Google': 'https://www.google.com/search?q=',
            'Bing': 'https://www.bing.com/search?q=',
            'Yahoo': 'https://search.yahoo.com/search?p=',
            'DuckDuckGo': 'https://duckduckgo.com/?q=',
            'Yandex': 'https://yandex.com/search/?text=',
            'Baidu': 'https://www.baidu.com/s?wd=',
            'Tor (DuckDuckGo)': 'https://3g2upl4pq6kufc4m.onion/?q='
        }
        
        # Dorking categories for DOMAIN-based searches
        self.domain_dork_categories = {
            'Website Information': {
                'Site Pages': 'site:{target}',
                'Cached Pages': 'cache:{target}',
                'Related Sites': 'related:{target}',
                'Site Info': 'info:{target}',
                'Site Links': 'link:{target}',
                'Subdomain Search': 'site:*.{target}',
                'Exclude Subdomain': 'site:{target} -site:www.{target}'
            },
            
            'File Types': {
                'PDF Files': 'site:{target} filetype:pdf',
                'DOC Files': 'site:{target} filetype:doc',
                'XLS Files': 'site:{target} filetype:xls',
                'PPT Files': 'site:{target} filetype:ppt',
                'TXT Files': 'site:{target} filetype:txt',
                'XML Files': 'site:{target} filetype:xml',
                'SQL Files': 'site:{target} filetype:sql',
                'Log Files': 'site:{target} filetype:log',
                'Config Files': 'site:{target} filetype:conf OR filetype:config'
            },
            
            'Login Pages': {
                'Admin Login': 'site:{target} inurl:admin',
                'Login Pages': 'site:{target} inurl:login',
                'Admin Panel': 'site:{target} "admin panel"',
                'Dashboard': 'site:{target} inurl:dashboard',
                'Control Panel': 'site:{target} "control panel"',
                'User Login': 'site:{target} "user login"',
                'Member Login': 'site:{target} "member login"'
            },
            
            'Directories': {
                'Directory Listing': 'site:{target} intitle:"index of"',
                'Parent Directory': 'site:{target} intitle:"parent directory"',
                'Backup Directory': 'site:{target} inurl:backup',
                'Admin Directory': 'site:{target} inurl:admin',
                'Upload Directory': 'site:{target} inurl:upload',
                'Include Directory': 'site:{target} inurl:include',
                'Config Directory': 'site:{target} inurl:config'
            },
            
            'Sensitive Information': {
                'Passwords': 'site:{target} "password" OR "pwd" OR "passwd"',
                'Database': 'site:{target} "database" OR "db" filetype:sql',
                'API Keys': 'site:{target} "api_key" OR "apikey" OR "api-key"',
                'Connection Strings': 'site:{target} "connection string" OR "connectionstring"',
                'Error Messages': 'site:{target} "error" OR "exception" OR "warning"',
                'Email Lists': 'site:{target} "@{target}" filetype:txt',
                'Phone Numbers': 'site:{target} "phone" OR "tel" OR "mobile"'
            },
            
            'Technology Stack': {
                'PHP Info': 'site:{target} "phpinfo()" OR "php version"',
                'Server Info': 'site:{target} "server status" OR "server info"',
                'Apache Status': 'site:{target} "apache" intitle:"status"',
                'MySQL': 'site:{target} "mysql" OR "phpmyadmin"',
                'WordPress': 'site:{target} inurl:wp-admin OR inurl:wp-content',
                'Joomla': 'site:{target} inurl:administrator OR inurl:joomla',
                'Drupal': 'site:{target} inurl:drupal OR "powered by drupal"'
            },
            
            'Social Media': {
                'Facebook': 'site:facebook.com "{target}"',
                'Twitter': 'site:twitter.com "{target}"',
                'LinkedIn': 'site:linkedin.com "{target}"',
                'Instagram': 'site:instagram.com "{target}"',
                'YouTube': 'site:youtube.com "{target}"',
                'Reddit': 'site:reddit.com "{target}"',
                'GitHub': 'site:github.com "{target}"'
            },
            
            'Email Intelligence': {
                'Email Addresses': '"{target}" "@" -site:{target}',
                'Email in PDFs': 'filetype:pdf "@{target}"',
                'Mailing Lists': 'intext:"@{target}" "mailing list"',
                'Contact Pages': 'intext:"@{target}" "contact"',
                'Staff Directory': 'site:{target} "staff" OR "directory" OR "team"'
            },
            
            'Security': {
                'Robots.txt': 'site:{target} inurl:robots.txt',
                'Sitemap': 'site:{target} inurl:sitemap.xml',
                'HTTP Security Headers': 'site:{target} "strict-transport-security"',
                'SSL Certificates': 'site:{target} "ssl certificate"',
                'Security Vulnerabilities': 'site:{target} "vulnerability" OR "exploit"',
                'Backup Files': 'site:{target} inurl:backup OR filetype:bak',
                'Test Pages': 'site:{target} inurl:test OR intitle:test'
            },

            'Extension':{
                'Log File': 'site:{target} ext:log',
                'TXT File': 'site:{target} ext:txt', 
                'conf Config File': 'site:{target} ext:conf', 
                'cnf Config File': 'site:{target} ext:cnf', 
                'ini Config File': 'site:{target} ext:ini', 
                'ENV File': 'site:{target} ext:env', 
                'Bash File': 'site:{target} ext:sh', 
                'bak Backup File': 'site:{target} ext:bak', 
                'Backup File': 'site:{target} ext:backup', 
                'SWAP File': 'site:{target} ext:swp', 
                'OLD File': 'site:{target} ext:old', 
                'Hidden or Non-Standard Files': 'site:{target} ext:~', 
                'GIT DATA': 'site:{target} ext:git', 
                'SVN File': 'site:{target} ext:svn', 
                'HTPASSWD File': 'site:{target} ext:htpasswd', 
                'HTACCESS File': 'site:{target} ext:htaccess', 
                'JSON File': 'site:{target} ext:json'
            }
        }
        
        # Dorking categories for KEYWORD-based searches
        self.keyword_dork_categories = {
            'Personal Information': {
                'Exclude Domain': '"{target}" -site:{exclude_domain}',
                'Social Profiles': '"{target}" site:linkedin.com OR site:facebook.com OR site:twitter.com',
                'Email Search': '"{target}" "@" filetype:xls OR filetype:xlsx OR filetype:csv',
                'Phone Numbers': '"{target}" "phone" OR "mobile" OR "tel"',
                'Address Search': '"{target}" "address" OR "street" OR "city"',
                'Resume/CV': '"{target}" filetype:pdf "resume" OR "cv"',
                'Contact Info': '"{target}" "contact" OR "email" OR "phone"'
            },
            
            'Professional': {
                'Job Title': '"{target}" "CEO" OR "CTO" OR "Manager" OR "Director"',
                'Company Search': '"{target}" "company" OR "corporation" OR "inc"',
                'Presentations': '"{target}" filetype:ppt OR filetype:pptx',
                'Documents': '"{target}" filetype:doc OR filetype:docx',
                'Spreadsheets': '"{target}" filetype:xls OR filetype:xlsx',
                'Work History': '"{target}" "worked at" OR "former" OR "previous"',
                'Skills': '"{target}" "skills" OR "experience" OR "expertise"'
            },
            
            'Education': {
                'Academic Papers': '"{target}" filetype:pdf "university" OR "research"',
                'Thesis/Dissertation': '"{target}" "thesis" OR "dissertation" filetype:pdf',
                'Student Records': '"{target}" "student" OR "graduate" OR "alumni"',
                'Publications': '"{target}" "published" OR "author" OR "journal"',
                'Conference Papers': '"{target}" "conference" OR "proceedings" filetype:pdf'
            },
            
            'Legal/Records': {
                'Court Records': '"{target}" "court" OR "lawsuit" OR "legal"',
                'News Articles': '"{target}" site:news.google.com OR site:reuters.com',
                'Press Releases': '"{target}" "press release" OR "announcement"',
                'Patents': '"{target}" "patent" OR "invention" site:patents.google.com',
                'Licenses': '"{target}" "license" OR "certified" OR "registration"'
            },
            
            'Social Media Deep': {
                'Facebook Deep': '"{target}" site:facebook.com -inurl:pages',
                'LinkedIn Deep': '"{target}" site:linkedin.com inurl:in',
                'Twitter Deep': '"{target}" site:twitter.com OR site:x.com',
                'Instagram Deep': '"{target}" site:instagram.com',
                'Reddit Posts': '"{target}" site:reddit.com',
                'YouTube Videos': '"{target}" site:youtube.com',
                'Pinterest': '"{target}" site:pinterest.com',
                'TikTok': '"{target}" site:tiktok.com'
            },
            
            'Forums/Communities': {
                'Forum Posts': '"{target}" "forum" OR "community" OR "discussion"',
                'Stack Overflow': '"{target}" site:stackoverflow.com',
                'GitHub': '"{target}" site:github.com',
                'Quora': '"{target}" site:quora.com',
                'Reddit AMA': '"{target}" site:reddit.com "AMA"',
                'Blog Comments': '"{target}" "comment" OR "replied"'
            },
            
            'Data Breaches': {
                'Paste Sites': '"{target}" site:pastebin.com OR site:paste.org',
                'Leaked Data': '"{target}" "password" OR "hack" OR "breach"',
                'Database Dumps': '"{target}" filetype:sql OR filetype:db',
                'Config Files': '"{target}" filetype:conf OR filetype:config',
                'Log Files': '"{target}" filetype:log "password" OR "email"'
            },
            
            'Geographic': {
                'Location Based': '"{target}" "city" OR "state" OR "country"',
                'Maps/GPS': '"{target}" site:maps.google.com OR "coordinates"',
                'Local Business': '"{target}" "business" OR "store" OR "shop"',
                'Real Estate': '"{target}" "property" OR "real estate" OR "address"',
                'Travel': '"{target}" "travel" OR "hotel" OR "flight"'
            },
            
            'Images/Media': {
                'Image Search': '"{target}" filetype:jpg OR filetype:png OR filetype:gif',
                'Video Search': '"{target}" filetype:mp4 OR filetype:avi OR filetype:mov',
                'Audio Search': '"{target}" filetype:mp3 OR filetype:wav',
                'Photo Metadata': '"{target}" "exif" OR "metadata" filetype:jpg',
                'Reverse Image': '"{target}" "reverse image" OR "tineye"'
            }
        }
        
        self.setup_ui()
    
    def on_search_type_change(self):
        """Handle search type change between Domain and Keyword"""
        search_type = self.search_type_var.get()
        if search_type == 'Domain':
            self.target_label.config(text="Target (domain):")
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, "example.com")
        else:  # Keyword
            self.target_label.config(text="Target (keyword/person):")
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, "John Doe")
        
        # Refresh categories and dorks
        self.refresh_categories()
        
    def get_current_dork_categories(self):
        """Return appropriate dork categories based on search type"""
        if self.search_type_var.get() == 'Domain':
            return self.domain_dork_categories
        else:
            return self.keyword_dork_categories
    
    def refresh_categories(self):
        """Refresh the categories listbox based on current search type"""
        # Clear existing categories
        self.categories_listbox.delete(0, tk.END)
        
        # Add new categories
        current_categories = self.get_current_dork_categories()
        for category in current_categories.keys():
            self.categories_listbox.insert(tk.END, category)
        
        # Select first category
        if self.categories_listbox.size() > 0:
            self.categories_listbox.selection_set(0)
            self.on_category_select(None)
    
    def setup_ui(self):
        # Main container
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(main_frame, text="OSINT Dorking Tool", 
                              font=('Arial', 18, 'bold'), 
                              fg='#ffffff', bg='#2b2b2b')
        title_label.pack(pady=(0, 20))
        
        # Input frame
        input_frame = tk.Frame(main_frame, bg='#2b2b2b')
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Target type selection
        target_type_frame = tk.Frame(input_frame, bg='#2b2b2b')
        target_type_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(target_type_frame, text="Search Type:", 
                font=('Arial', 10), fg='#ffffff', bg='#2b2b2b').pack(side=tk.LEFT)
        
        self.search_type_var = tk.StringVar(value='Domain')
        domain_radio = tk.Radiobutton(target_type_frame, text='Domain', 
                                     variable=self.search_type_var, value='Domain',
                                     fg='#ffffff', bg='#2b2b2b', selectcolor='#4b4b4b',
                                     command=self.on_search_type_change)
        domain_radio.pack(side=tk.LEFT, padx=(10, 5))
        
        keyword_radio = tk.Radiobutton(target_type_frame, text='Keyword', 
                                      variable=self.search_type_var, value='Keyword',
                                      fg='#ffffff', bg='#2b2b2b', selectcolor='#4b4b4b',
                                      command=self.on_search_type_change)
        keyword_radio.pack(side=tk.LEFT, padx=(5, 0))
        
        # Target input
        self.target_label = tk.Label(input_frame, text="Target (domain):", 
                font=('Arial', 10), fg='#ffffff', bg='#2b2b2b')
        self.target_label.pack(anchor=tk.W)
        
        self.target_entry = tk.Entry(input_frame, font=('Arial', 12), width=50)
        self.target_entry.pack(fill=tk.X, pady=(5, 10))
        self.target_entry.insert(0, "example.com")
        
        # Search engine selection
        engine_frame = tk.Frame(input_frame, bg='#2b2b2b')
        engine_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(engine_frame, text="Search Engine:", 
                font=('Arial', 10), fg='#ffffff', bg='#2b2b2b').pack(side=tk.LEFT)
        
        self.engine_var = tk.StringVar(value='Google')
        engine_combo = ttk.Combobox(engine_frame, textvariable=self.engine_var, 
                                   values=list(self.search_engines.keys()), 
                                   state='readonly', width=20)
        engine_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # Main Content frame
        content_frame = tk.Frame(main_frame, bg='#2b2b2b')
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Categories
        left_frame = tk.Frame(content_frame, bg='#3b3b3b', width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_frame.pack_propagate(False)
        
        tk.Label(left_frame, text="Dork Categories", 
                font=('Arial', 12, 'bold'), fg='#ffffff', bg='#3b3b3b').pack(pady=10)
        
        # Categories listbox
        self.categories_listbox = tk.Listbox(left_frame, font=('Arial', 10), 
                                           bg='#4b4b4b', fg='#ffffff',
                                           selectbackground='#0078d4')
        self.categories_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        for category in self.domain_dork_categories.keys():
            self.categories_listbox.insert(tk.END, category)
        
        self.categories_listbox.bind('<<ListboxSelect>>', self.on_category_select)
        
        # Right panel - Dorks
        right_frame = tk.Frame(content_frame, bg='#3b3b3b')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(right_frame, text="Available Dorks", 
                font=('Arial', 12, 'bold'), fg='#ffffff', bg='#3b3b3b').pack(pady=10)
        
        # Dorks frame
        dorks_frame = tk.Frame(right_frame, bg='#3b3b3b')
        dorks_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        
        # Scrollable frame for dork buttons
        canvas = tk.Canvas(dorks_frame, bg='#3b3b3b')
        scrollbar = ttk.Scrollbar(dorks_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg='#3b3b3b')
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bottom frame - Generated query and actions
        bottom_frame = tk.Frame(main_frame, bg='#2b2b2b')
        bottom_frame.pack(fill=tk.X, pady=(20, 0))
        
        tk.Label(bottom_frame, text="Generated Query:", 
                font=('Arial', 10), fg='#ffffff', bg='#2b2b2b').pack(anchor=tk.W)
        
        self.query_text = scrolledtext.ScrolledText(bottom_frame, height=3, 
                                                   font=('Consolas', 10),
                                                   bg='#4b4b4b', fg='#ffffff')
        self.query_text.pack(fill=tk.X, pady=(5, 10))
        
        # Action buttons
        buttons_frame = tk.Frame(bottom_frame, bg='#2b2b2b')
        buttons_frame.pack(fill=tk.X)
        
        search_btn = tk.Button(buttons_frame, text="🔍 Search", 
                              command=self.execute_search,
                              bg='#0078d4', fg='white', 
                              font=('Arial', 10, 'bold'),
                              padx=20, pady=5)
        search_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        copy_btn = tk.Button(buttons_frame, text="📋 Copy Query", 
                            command=self.copy_query,
                            bg='#107c10', fg='white', 
                            font=('Arial', 10, 'bold'),
                            padx=20, pady=5)
        copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        clear_btn = tk.Button(buttons_frame, text="🗑️ Clear", 
                             command=self.clear_query,
                             bg='#d83b01', fg='white', 
                             font=('Arial', 10, 'bold'),
                             padx=20, pady=5)
        clear_btn.pack(side=tk.LEFT)
        
        # Status label
        self.status_label = tk.Label(buttons_frame, text="Ready", 
                                    font=('Arial', 9), fg='#cccccc', bg='#2b2b2b')
        self.status_label.pack(side=tk.RIGHT)
        
        # Initialize with first category
        self.categories_listbox.selection_set(0)
        self.on_category_select(None)
    
    def on_category_select(self, event):
        selection = self.categories_listbox.curselection()
        if not selection:
            return
        
        category = self.categories_listbox.get(selection[0])
        self.populate_dorks(category)
    
    def populate_dorks(self, category):
        # Clear existing buttons
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        current_categories = self.get_current_dork_categories()
        if category not in current_categories:
            return
        
        dorks = current_categories[category]
        
        for i, (name, query) in enumerate(dorks.items()):
            btn = tk.Button(self.scrollable_frame, text=name,
                           command=lambda q=query, n=name: self.add_dork(q, n),
                           bg='#4b4b4b', fg='#ffffff',
                           font=('Arial', 9), pady=5,
                           relief=tk.RAISED, bd=1,
                           anchor=tk.W, width=40)
            btn.pack(fill=tk.X, padx=5, pady=2)
            
            # Add tooltip with query preview
            self.create_tooltip(btn, query)
    
    def create_tooltip(self, widget, text):
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            tooltip.configure(bg='#404040')
            
            label = tk.Label(tooltip, text=text, 
                           bg='#404040', fg='#ffffff',
                           font=('Consolas', 8),
                           wraplength=300)
            label.pack()
            
            widget.tooltip = tooltip
        
        def on_leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                del widget.tooltip
        
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)
    
    def add_dork(self, query, name):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target domain or keyword!")
            return
        
        # Handle special case for keyword search with domain exclusion
        if self.search_type_var.get() == 'Keyword' and '{exclude_domain}' in query:
            # For keyword searches, ask for domain to exclude
            exclude_domain = self.ask_exclude_domain()
            if exclude_domain:
                formatted_query = query.format(target=target, exclude_domain=exclude_domain)
            else:
                # If no exclude domain provided, remove the exclusion part
                formatted_query = f'"{target}"'
        else:
            # Replace placeholder with actual target
            formatted_query = query.format(target=target)
        
        # Add to query text
        current_text = self.query_text.get(1.0, tk.END).strip()
        if current_text:
            self.query_text.insert(tk.END, f"\n{formatted_query}")
        else:
            self.query_text.insert(tk.END, formatted_query)
        
        self.status_label.config(text=f"Added: {name}")
        
        # Auto-scroll to bottom
        self.query_text.see(tk.END)
    
    def ask_exclude_domain(self):
        """Ask user for domain to exclude in keyword searches"""
        domain = simpledialog.askstring("Exclude Domain", 
                                       "Enter domain to exclude (optional):\nExample: linkedin.com",
                                       initialvalue="")
        return domain if domain else None
    
    def execute_search(self):
        query = self.query_text.get(1.0, tk.END).strip()
        if not query:
            messagebox.showwarning("Warning", "No query to search!")
            return
        
        engine = self.engine_var.get()
        if engine not in self.search_engines:
            messagebox.showerror("Error", "Invalid search engine selected!")
            return
        
        # Encode query for URL
        encoded_query = urllib.parse.quote_plus(query)
        search_url = self.search_engines[engine] + encoded_query
        
        try:
            webbrowser.open(search_url)
            self.status_label.config(text=f"Opened search in {engine}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open browser: {str(e)}")
    
    def copy_query(self):
        query = self.query_text.get(1.0, tk.END).strip()
        if not query:
            messagebox.showwarning("Warning", "No query to copy!")
            return
        
        self.root.clipboard_clear()
        self.root.clipboard_append(query)
        self.status_label.config(text="Query copied to clipboard")
    
    def clear_query(self):
        self.query_text.delete(1.0, tk.END)
        self.status_label.config(text="Query cleared")

def main():
    root = tk.Tk()
    app = OSINTDorkingTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
