#!/bin/bash
# Agentic Security Dashboard - Fly.io Deployment Script
# ======================================================
# Usage: ./deploy.sh [setup|deploy|logs|ssh]

set -e

APP_NAME="agentic-security-dashboard"
REGION="ord"  # Chicago - change as needed

show_help() {
    echo "Agentic Security Dashboard - Fly.io Deployment"
    echo ""
    echo "Usage: ./deploy.sh <command>"
    echo ""
    echo "Commands:"
    echo "  setup    - First-time setup (create app, volume, secrets)"
    echo "  deploy   - Deploy or redeploy the application"
    echo "  logs     - View application logs"
    echo "  ssh      - SSH into the running machine"
    echo "  status   - Check application status"
    echo "  destroy  - Destroy the application (WARNING: deletes data)"
    echo ""
}

check_fly_cli() {
    if ! command -v fly &> /dev/null; then
        echo "❌ Fly CLI not installed. Install from: https://fly.io/docs/hands-on/install-flyctl/"
        exit 1
    fi
}

setup() {
    echo "🚀 Setting up Agentic Security Dashboard on Fly.io..."
    
    check_fly_cli
    
    # Check if logged in
    if ! fly auth whoami &> /dev/null; then
        echo "📝 Please log in to Fly.io..."
        fly auth login
    fi
    
    # Launch app (creates app without deploying)
    echo "📦 Creating Fly.io application..."
    fly launch --copy-config --no-deploy --name "$APP_NAME" --region "$REGION" || true
    
    # Create persistent volume
    echo "💾 Creating persistent volume..."
    fly volumes create agentic_data --size 1 --region "$REGION" --yes || true
    
    # Set secrets
    echo ""
    echo "🔐 Setting secrets..."
    echo "   You'll be prompted for a DASHBOARD_TOKEN."
    echo "   This is the password to access the dashboard."
    echo ""
    
    read -p "Enter DASHBOARD_TOKEN (or press Enter for random): " token
    if [ -z "$token" ]; then
        token=$(openssl rand -hex 16)
        echo "   Generated token: $token"
    fi
    
    secret_key=$(openssl rand -hex 32)
    
    fly secrets set \
        DASHBOARD_TOKEN="$token" \
        SECRET_KEY="$secret_key"
    
    echo ""
    echo "✅ Setup complete! Run './deploy.sh deploy' to deploy."
    echo ""
    echo "📝 Your dashboard token: $token"
    echo "   Save this - you'll need it to log in!"
}

deploy() {
    echo "🚀 Deploying to Fly.io..."
    check_fly_cli
    
    fly deploy
    
    echo ""
    echo "✅ Deployment complete!"
    echo ""
    echo "🌐 Your dashboard is available at: https://$APP_NAME.fly.dev"
    echo ""
    echo "📊 View logs: ./deploy.sh logs"
    echo "🔧 SSH access: ./deploy.sh ssh"
}

logs() {
    check_fly_cli
    fly logs
}

ssh_connect() {
    check_fly_cli
    fly ssh console
}

status() {
    check_fly_cli
    echo "📊 Application Status:"
    fly status
    echo ""
    echo "💾 Volumes:"
    fly volumes list
    echo ""
    echo "🔐 Secrets (names only):"
    fly secrets list
}

destroy() {
    check_fly_cli
    echo "⚠️  WARNING: This will delete the app and ALL DATA!"
    read -p "Type '$APP_NAME' to confirm: " confirm
    if [ "$confirm" == "$APP_NAME" ]; then
        fly apps destroy "$APP_NAME" --yes
        echo "✅ Application destroyed."
    else
        echo "❌ Cancelled."
    fi
}

# Main
case "${1:-help}" in
    setup)
        setup
        ;;
    deploy)
        deploy
        ;;
    logs)
        logs
        ;;
    ssh)
        ssh_connect
        ;;
    status)
        status
        ;;
    destroy)
        destroy
        ;;
    *)
        show_help
        ;;
esac

