#!/usr/bin/env python3

# TODO: make sure we have all possible functions
# TODO: do we need the full prototype here? Seems like methods with the same
# name redirect to the same methods, regardless of the arguments. Double check
# this and simplify if needed.
DEFAULT_METHODS_PER_USAGE = {
    # TODO:
    # Activities
    'startActivity(Landroid/content/Intent;)V':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
    ],
    'startActivity(Landroid/content/Intent; Landroid/os/Bundle;)V':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
    ],
    'startActivity(Landroid/content/Intent; I)V':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
    ],
    'startActivity(Landroid/content/Intent; I Landroid/os/Bundle;)V':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
    ],
    'startActivityForResult(Landroid/content/Intent; I)V':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
    ],
    'startActivityForResult(Landroid/content/Intent; I Landroid/os/Bundle;)V':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
    ],
    # Threads
    # AsyncTasks
    'execute([Ljava/lang/Object;)Landroid/os/AsyncTask;': [
        'onPreExecute',
        'doInBackground',
        'onProgressUpdate',
        'onPostExecute'
    ],

    'execute(Ljava/util/concurrent/Executor; [Ljava/lang/Object;)Landroid/os/AsyncTask;': [
        'onPreExecute',
        'doInBackground',
        'onProgressUpdate',
        'onPostExecute'
    ],

    # Executor
    # ThreadPoolExecutor
    # FutureTask

    # Services
    'startService(Landroid/content/Intent;)Landroid/content/ComponentName;':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
    ],
    'startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;':[
        'onCreate',
        # onStart was deprecated in favor of onStartCommand at API level 15
        [
            'onStart',
            'onStartCommand'
        ],
        # TODO: not sure that this is called all the time
        'startForeground',
    ],
    'stopService(Landroid/content/Intent;)Z':[
        'onDestroy',
    ],

    # Bound services
    'bindIsolatedService(Landroid/content/Intent; I Ljava/lang/String; Ljava/util/concurrent/Executor; Landroid/content/ServiceConnection;)Z':[
        'onCreate',
        # 'onServiceConnected'
        'onBind'
    ],
    'bindService(Landroid/content/Intent; I Ljava/util/concurrent/Executor; Landroid/content/ServiceConnection;)Z':[
        'onCreate',
        # 'onServiceConnected'
        'onBind'
    ],
    'bindService(Landroid/content/Intent; Landroid/content/ServiceConnection; I)Z':[
        'onCreate',
        # 'onServiceConnected'
        'onBind'
    ],
    'bindServiceAsUser(Landroid/content/Intent; Landroid/content/ServiceConnection; I Landroid/os/UserHandle;)Z':[
        'onCreate',
        # 'onServiceConnected'
        'onBind'
    ],
    # TODO: what about 'onServiceDisconnected'?
    'unbindService(Landroid/content/ServiceConnection;)V':[
        'onUnbind',
        'onDestroy',
    ],

    # Broadcast receivers
    'sendBroadcast(Landroid/content/Intent; Ljava/lang/String;)V': [
        'onReceive',
    ],
    'sendBroadcast(Landroid/content/Intent;)V': [
        'onReceive',
    ],
    'sendBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle;)V': [
        'onReceive',
    ],
    'sendBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Ljava/lang/String;)V': [
        'onReceive',
    ],
    'sendBroadcastWithMultiplePermissions(Landroid/content/Intent; [Ljava/util/String;)V': [
        'onReceive',
    ],
    'sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V': [
        'onReceive',
    ],
    'sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V': [
        'onReceive',
    ],
    'sendOrderedBroadcast(Landroid/content/Intent; Ljava/lang/String;)V': [
        'onReceive',
    ],
    'sendOrderedBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Ljava/lang/String; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V': [
        'onReceive',
    ],
    'sendStickyBroadcast(Landroid/content/Intent;)V': [
        'onReceive',
    ],
    'sendStickyBroadcast(Landroid/content/Intent; Landroid/os/Bundle)V': [
        'onReceive',
    ],
    'sendStickyBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle;)V': [
        'onReceive',
    ],
    'sendStickyOrderedBroadcast(Landroid/content/Intent; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V': [
        'onReceive',
    ],
    'sendStickyOrderedBroadcastAsUser(Landroid/content/Intent; Landroid/os/UserHandle; Landroid/content/BroadcastReceiver; Landroid/os/Handler; I Ljava/lang/String; Landroid/os/Bundle;)V': [
        'onReceive',
    ],
}

DEFAULT_METHODS = set()
for methods in DEFAULT_METHODS_PER_USAGE.values():
    for item in methods:
        if isinstance(item, list):
            for i in item:
                DEFAULT_METHODS.add(i)
        else:
            DEFAULT_METHODS.add(item)

DEFAULT_ENTRYPOINTS = {
    'activity' : [
        ('onCreate', '(Landroid/os/Bundle;)V'),
        ('onStart', '()V'),
        ('onResume', '()V'),
        ('onRestart', '()V'),
        ('onPause', '()V'),
        ('onStop', '()V'),
        ('onDestroy', '()V'),
    ],
    'activity-alias' : [
        ('onCreate', '(Landroid/os/Bundle;)V'),
        ('onStart', '()V'),
        ('onResume', '()V'),
        ('onRestart', '()V'),
        ('onPause', '()V'),
        ('onStop', '()V'),
        ('onDestroy', '()V'),
    ],
    'service' : [
        ('onCreate', '()V'),
        ('onStartCommand', '(Landroid/os/Intent; I I)I'),
        ('onBind', '(Landroid/os/Intent;)Landroid/os/IBinder;'),
        ('onUnbind', '(Landroid/os/Intent;)Z'),
        ('onRebind', '(Landroid/os/Intent;)V'),
        ('onDestroy', '()V'),
    ],
    'receiver' : [
        ('onReceive', '(Landroid/content/Context; Landroid/content/Intent;)V'),
    ],
    'provider' : [
        ('onCreate', '()Z'),
        ('query', '(Landroid/net/Uri; [Ljava/lang/String; Landroid/os/Bundle; Landroid/os/CancellationSignal;)Landroid/database/Cursor;'),
        ('query', '(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String; Landroid/os/CancellationSignal;)Landroid/database/Cursor;'),
        ('query', '(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;'),
        ('insert', '(Landroid/net/Uri; Landroid/content/ContentValues;)Landroid/net/Uri;'),
        ('insert', '(Landroid/net/Uri; Landroid/content/ContentValues; Landroid/os/Bundle;)Landroid/net/Uri;'),
        ('update', '(Landroid/net/Uri; Landroid/content/ContentValues; Landroid/os/Bundle;)I'),
        ('update', '(Landroid/net/Uri; Landroid/content/ContentValues; [Ljava/lang/String; Ljava/lang/String;)I'),
        ('delete', '(Landroid/net/Uri; Landroid/os/Bundle;)I'),
        ('delete', '(Landroid/net/Uri; Ljava/lang/String; [Ljava/lang/String;)I'),
        ('getType', '(Landroid/net/Uri;)Ljava/lang/String;')
    ]
}
