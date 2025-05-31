
import os
import shutil

class FileProcessor:
    """Utility for processing and organizing files"""
    
    def __init__(self, work_dir):
        self.work_dir = work_dir
    
    def clean_temp_files(self):
        """Clean temporary files"""
        temp_patterns = ['*.tmp', '*.temp', '.DS_Store']
        for pattern in temp_patterns:
            for file in os.glob(os.path.join(self.work_dir, pattern)):
                os.remove(file)
    
    def backup_files(self, backup_dir):
        """Backup important files"""
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        for file in os.listdir(self.work_dir):
            if file.endswith(('.py', '.txt', '.json')):
                shutil.copy2(os.path.join(self.work_dir, file), backup_dir)
    
    def organize_downloads(self):
        """Organize downloaded files by type"""
        downloads = os.path.expanduser('~/Downloads')
        for file in os.listdir(downloads):
            # Move files to appropriate folders
            if file.endswith('.pdf'):
                shutil.move(os.path.join(downloads, file), 
                          os.path.join(downloads, 'PDFs', file))

# Usage
processor = FileProcessor('/tmp/workspace')
processor.clean_temp_files()
