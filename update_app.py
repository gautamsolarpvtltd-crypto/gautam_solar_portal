#!/usr/bin/env python3
"""
Automatic Route Updater for enhanced_app.py
Run this script to automatically add Company Documents route
"""

import os
import re

def update_enhanced_app():
    """Add company docs route to enhanced_app.py"""
    
    if not os.path.exists('enhanced_app.py'):
        print("❌ Error: enhanced_app.py not found!")
        print("   Make sure you're in the correct directory.")
        return False
    
    # Read current content
    with open('enhanced_app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if route already exists
    if '@app.route("/admin/company-docs")' in content:
        print("✅ Company Documents route already exists!")
        return True
    
    # Find where to insert (after admin/certificates route)
    route_to_add = """
@app.route("/admin/company-docs")
@admin_required
def admin_company_docs():
    """Admin page for managing company documents"""
    return render_template("admin_company_docs.html")
"""
    
    # Find the position after @app.route("/admin/certificates")
    pattern = r'(@app\.route\("/admin/certificates"\)[\s\S]*?def admin_certificates\(\):[\s\S]*?return render_template\([^)]+\))'
    
    match = re.search(pattern, content)
    
    if match:
        insert_position = match.end()
        new_content = content[:insert_position] + "\n" + route_to_add + content[insert_position:]
        
        # Backup original file
        with open('enhanced_app.py.backup', 'w', encoding='utf-8') as f:
            f.write(content)
        print("✅ Backup created: enhanced_app.py.backup")
        
        # Write updated content
        with open('enhanced_app.py', 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print("✅ Successfully added Company Documents route!")
        print("   Route added at line:", content[:insert_position].count('\n') + 1)
        print("\n📝 Next steps:")
        print("   1. Restart Flask application: python enhanced_app.py")
        print("   2. Access: http://127.0.0.1:5000/admin/company-docs")
        return True
    else:
        print("❌ Could not find insertion point.")
        print("   Please add the route manually using ADD_ROUTE_INSTRUCTIONS.txt")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("🔧 Enhanced App Route Updater")
    print("=" * 60)
    print()
    update_enhanced_app()
    print()
    print("=" * 60)
