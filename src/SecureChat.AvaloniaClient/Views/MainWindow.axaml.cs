using System;
using System.Collections.Specialized;
using Avalonia.Controls;
using Avalonia.Threading;
using SecureChat.AvaloniaClient.ViewModels;

namespace SecureChat.AvaloniaClient.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        
        // Subscribe to DataContext changes để setup auto-scroll
        DataContextChanged += OnDataContextChanged;
    }
    
    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        Console.WriteLine($"[MainWindow] OnDataContextChanged called. DataContext type: {DataContext?.GetType().Name}");
        
        if (DataContext is MainViewModel viewModel)
        {
            Console.WriteLine($"[MainWindow] DataContext is MainViewModel. Messages.Count: {viewModel.Messages.Count}");
            
            // Set StorageProvider for file dialogs
            viewModel.StorageProvider = StorageProvider;
            
            // Subscribe to Messages collection changes
            viewModel.Messages.CollectionChanged += OnMessagesCollectionChanged;
            
            Console.WriteLine("[MainWindow] Subscribed to Messages.CollectionChanged");
        }
        else
        {
            Console.WriteLine($"[MainWindow] DataContext is NOT MainViewModel! Type: {DataContext?.GetType()}");
        }
    }
    
    private void OnMessagesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        Console.WriteLine($"[MainWindow] OnMessagesCollectionChanged: Action={e.Action}, NewItems={e.NewItems?.Count}");
        
        // Auto-scroll to bottom khi có tin nhắn mới
        if (e.Action == NotifyCollectionChangedAction.Add)
        {
            Dispatcher.UIThread.Post(() =>
            {
                Console.WriteLine("[MainWindow] Scrolling to end...");
                // Scroll to bottom
                ChatScrollViewer?.ScrollToEnd();
            }, DispatcherPriority.Background);
        }
    }
}